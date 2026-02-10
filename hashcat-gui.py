import os
import subprocess
import threading
import time
import signal
from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SYSTEM_RULES_FOLDER'] = '/usr/share/hashcat/rules'
app.config['SYSTEM_WORDLISTS_FOLDER'] = '/usr/share/wordlists'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'dic', 'lst', 'rule', 'words'}

job_status = {
    'running': False,
    'progress': 'Idle',
    'eta': 'N/A',
    'recovered': None,
    'output_file': None,
    'current_job': '',
    'cmd': '',
    'log_tail': '',
    'last_update': 0,
    'return_code': None,
    'error': None
}


current_process = {'popen': None}
process_lock = threading.Lock()


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def safe_join_system_rules(rule_filename: str) -> str:
    """
    Resolve a rule filename safely inside /usr/share/hashcat/rules.
    Prevents path traversal like ../../etc/passwd.
    """
    base = os.path.realpath(app.config['SYSTEM_RULES_FOLDER'])
    name = secure_filename(rule_filename)
    candidate = os.path.realpath(os.path.join(base, name))
    if not candidate.startswith(base + os.sep):
        raise ValueError("Invalid rule path")
    return candidate


def safe_join_system_wordlists(wordlist_relpath: str) -> str:
    """
    Resolve a wordlist path safely inside /usr/share/wordlists.
    Allows subdirectories, prevents traversal.
    """
    base = os.path.realpath(app.config['SYSTEM_WORDLISTS_FOLDER'])
    candidate = os.path.realpath(os.path.join(base, wordlist_relpath))

    if not candidate.startswith(base + os.sep):
        raise ValueError("Invalid wordlist path")

    return candidate


def run_pcap_convert(in_path: str, out_format: str):
    """
    Convert pcap/pcapng to hashcat-compatible format.
    """
    base, _ = os.path.splitext(in_path)

    if out_format == '22000':
        out_path = base + '.22000'
        cmd = ['hcxpcapngtool', '-o', out_path, in_path]

    elif out_format == 'hcwpax':
        out_path = base + '.hcwpax'
        cmd = ['hcxpcapngtool', '-o', out_path, in_path]

    elif out_format == 'hccapx':
        out_path = base + '.hccapx'
        cmd = ['hcxpcapngtool', '-o', out_path, in_path]

    else:
        raise ValueError('Unsupported output format')

    update_log(f"[pcap] running: {' '.join(cmd)}")

    try:
        subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        update_log(f"[pcap][error] {e.stdout}")
        raise RuntimeError('PCAP conversion failed')

    if not os.path.exists(out_path):
        raise RuntimeError('Output file not generated')

    return out_path


def detect_office_hash_mode(hash_line: str):
    """
    Detect Hashcat mode and friendly Office version from an extracted hash.
    """
    if hash_line.startswith('$office$'):
        if '*2007*' in hash_line:
            return '9400', 'MS Office 2007'
        if '*2010*' in hash_line:
            return '9500', 'MS Office 2010'
        if '*2013*' in hash_line:
            return '9600', 'MS Office 2013'
        if '*2016*' in hash_line:
            return '9600', 'MS Office 2016'
    elif hash_line.startswith('$oldoffice$'):
        return '9800', 'MS Office <= 2003'

    return None, 'Unknown Office Version'


def update_log(line: str, max_chars: int = 8000):
    """Append a line to the rolling log tail (keeps last max_chars)."""
    global job_status
    job_status['log_tail'] = (job_status.get('log_tail', '') + line + "\n")[-max_chars:]
    job_status['last_update'] = time.time()


def _set_current_process(p):
    with process_lock:
        current_process['popen'] = p


def _get_current_process():
    with process_lock:
        return current_process['popen']


def _clear_current_process(p):
    with process_lock:
        if current_process['popen'] is p:
            current_process['popen'] = None


def run_hashcat(hash_path: str, params: dict):
    global job_status

    job_status['running'] = True
    job_status['progress'] = 'Starting Hashcat...'
    job_status['eta'] = 'Calculating...'
    job_status['recovered'] = None
    job_status['output_file'] = None
    job_status['current_job'] = params.get('description', '')
    job_status['cmd'] = ''
    job_status['log_tail'] = ''
    job_status['last_update'] = time.time()
    job_status['return_code'] = None
    job_status['error'] = None

    potfile = os.path.join(app.config['UPLOAD_FOLDER'], 'hashcat.potfile')
    output_file = os.path.join(app.config['UPLOAD_FOLDER'], 'recovered.txt')

    cmd = [
        'hashcat',
        '-m', params['hash_mode'],
        '--potfile-path', potfile,
        '--remove',
        '--status',
        '--status-timer', '5'
    ]

    if params.get('rule'):
        cmd += ['-r', params['rule']]

    if params['attack_mode'] == '0':  
        cmd += ['-a', '0', hash_path, params['wordlist']]
    elif params['attack_mode'] == '3':  
        cmd += ['-a', '3', hash_path, params['mask']]
    elif params['attack_mode'] == '6':  
        cmd += ['-a', '6', hash_path, params['wordlist'], params['mask']]
    elif params['attack_mode'] == '7':  
        cmd += ['-a', '7', hash_path, params['mask'], params['wordlist']]

    if params.get('increment'):
        cmd += ['-i', '--increment-min', params['inc_min'], '--increment-max', params['inc_max']]

    job_status['cmd'] = " ".join(cmd)
    update_log(f"[cmd] {job_status['cmd']}")

    try:
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            preexec_fn=os.setsid  
        )
        _set_current_process(process)
    except FileNotFoundError:
        job_status['running'] = False
        job_status['error'] = "hashcat not found. Is hashcat installed and in PATH?"
        update_log("[error] hashcat not found. Install with: sudo apt install hashcat")
        job_status['progress'] = 'Error'
        _set_current_process(None)
        return

    try:
        for raw in process.stdout:
            line = (raw or "").strip()
            if not line:
                continue

            update_log(line)

            
            if 'Progress' in line:
                job_status['progress'] = line
            elif 'Time.Estimated' in line:
                
                parts = line.split(':', 1)
                if len(parts) == 2:
                    job_status['eta'] = parts[1].strip()
            elif 'Recovered' in line and 'Speed' not in line:
                job_status['progress'] = line
    finally:
        
        try:
            if process.stdout:
                process.stdout.close()
        except Exception:
            pass

    rc = process.wait()
    job_status['return_code'] = rc
    _clear_current_process(process)

    if job_status.get('progress') == 'Stopping...':
        job_status['progress'] = 'Stopped'
        update_log(f"[exit] stopped (return_code={rc})")
    elif rc != 0:
        job_status['error'] = f"hashcat exited with code {rc}"
        update_log(f"[exit] hashcat return_code={rc}")

    if os.path.exists(potfile):
        try:
            with open(potfile, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            lines = []
            update_log(f"[error] could not read potfile: {e}")

        if lines:
            results = []
            for ln in lines:
                ln = ln.strip()
                if ':' not in ln:
                    continue

                hash_part, pwd = ln.rsplit(':', 1)
                results.append(f"{hash_part} -> {pwd}")

            recovered_text = "\n".join(results)
            job_status['recovered'] = recovered_text or job_status['recovered'] or "None"
            try:
                with open(output_file, 'w', encoding='utf-8', errors='ignore') as out:
                    out.write(recovered_text)
                job_status['output_file'] = output_file
            except Exception as e:
                update_log(f"[error] could not write output file: {e}")

    job_status['running'] = False
    if job_status['progress'] not in ('Stopped', 'Error'):
        job_status['progress'] = 'Finished'
        update_log("[done] Finished")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/uploaded_wordlists')
def uploaded_wordlists():
    base = app.config['SYSTEM_WORDLISTS_FOLDER']
    if not os.path.isdir(base):
        return jsonify({
            'wordlists': [],
            'warning': f'Wordlists folder not found: {base}',
            'base': base
        }), 200

    allowed_ext = {'.txt', '.dic', '.lst', '.words'}
    out = []

    try:
        for root, _, files in os.walk(base):
            for name in files:
                _, ext = os.path.splitext(name)
                if ext.lower() not in allowed_ext:
                    continue

                full = os.path.join(root, name)
                if not os.path.isfile(full):
                    continue

                rel = os.path.relpath(full, base)
                out.append({
                    'file': rel,
                    'label': rel
                })
    except Exception as e:
        return jsonify({'wordlists': [], 'error': str(e), 'base': base}), 200

    return jsonify({'wordlists': sorted(out, key=lambda x: x['label'].lower()), 'base': base}), 200


@app.route('/tools/pcap', methods=['POST'])
def pcap_tool():
    pcap_file = request.files.get('pcap_file')
    out_format = request.form.get('format', '22000')

    if not pcap_file or not pcap_file.filename:
        return jsonify({'error': 'No PCAP file provided'}), 400

    if not pcap_file.filename.lower().endswith(('.pcap', '.pcapng')):
        return jsonify({'error': 'Invalid PCAP file type'}), 400

    in_path = os.path.join(
        app.config['UPLOAD_FOLDER'],
        secure_filename(pcap_file.filename)
    )
    pcap_file.save(in_path)

    try:
        out_path = run_pcap_convert(in_path, out_format)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    return send_file(
        out_path,
        as_attachment=True,
        download_name=os.path.basename(out_path)
    )


@app.route('/office_extract', methods=['POST'])
def office_extract():
    file = request.files.get('office_file')
    if not file or not file.filename:
        return jsonify({'error': 'No file uploaded'}), 400

    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    try:
        result = subprocess.check_output(
            ['python3', '/usr/share/john/office2john.py', path],
            text=True,
            stderr=subprocess.DEVNULL
        )

    except Exception as e:
        return jsonify({'error': f'Extraction failed: {e}'}), 500

    detected = []

    for line in result.splitlines():
        if not line.strip():
            continue

        mode, label = detect_office_hash_mode(line)

        detected.append({
            'hash': line,
            'mode': mode,
            'label': label
        })

    return jsonify({
        'success': True,
        'count': len(detected),
        'detected': detected
    })


@app.route('/rules')
def rules():
    base = app.config['SYSTEM_RULES_FOLDER']
    if not os.path.isdir(base):
        return jsonify({'rules': [], 'warning': f'Rules folder not found: {base}', 'base': base}), 200

    rules_list = []
    try:
        for name in sorted(os.listdir(base), key=lambda s: s.lower()):
            if not name.lower().endswith('.rule'):
                continue
            full = os.path.join(base, name)
            if os.path.isfile(full):
                rules_list.append({'file': name, 'label': name[:-5]})
    except Exception as e:
        return jsonify({'rules': [], 'error': str(e), 'base': base}), 200

    return jsonify({'rules': rules_list, 'base': base}), 200


@app.route('/stop', methods=['POST'])
def stop():
    """
    Stop the currently running hashcat job cleanly.
    Strategy:
      1) SIGINT to the process group (like Ctrl-C) -> gives hashcat chance to exit cleanly
      2) If still alive after a short wait, terminate
      3) If still alive, kill
    """
    p = _get_current_process()
    if not p or p.poll() is not None:
        return jsonify({'message': 'No running job to stop.'}), 200

    job_status['progress'] = 'Stopping...'
    job_status['error'] = None
    update_log("[ui] stop requested")

    try:
        os.killpg(os.getpgid(p.pid), signal.SIGINT)
        update_log("[stop] sent SIGINT")
    except Exception as e:
        update_log(f"[stop] SIGINT failed: {e}")

    deadline = time.time() + 5
    while time.time() < deadline:
        if p.poll() is not None:
            return jsonify({'message': 'Stop signal sent. Job stopping.'}), 200
        time.sleep(0.2)

    try:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        update_log("[stop] sent SIGTERM")
    except Exception as e:
        update_log(f"[stop] SIGTERM failed: {e}")

    deadline = time.time() + 3
    while time.time() < deadline:
        if p.poll() is not None:
            return jsonify({'message': 'Job terminated.'}), 200
        time.sleep(0.2)

    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        update_log("[stop] sent SIGKILL")
    except Exception as e:
        update_log(f"[stop] SIGKILL failed: {e}")

    return jsonify({'message': 'Kill signal sent.'}), 200


@app.route('/upload', methods=['POST'])
def upload():
    if job_status.get('running'):
        return jsonify({'error': 'A job is already running. Stop it before starting a new one.'}), 400

    hash_file = request.files.get('hash_file')
    wordlist_file = request.files.get('wordlist_file')
    rule_file = request.files.get('rule_file')

    hash_mode = request.form.get('hash_mode')
    attack_mode = request.form.get('attack_mode')
    mask = request.form.get('mask', '').strip()
    hybrid_position = request.form.get('hybrid_position', 'append')
    rule_preset = request.form.get('rule_preset', '').strip()
    wordlist_preset = request.form.get('wordlist_preset', '').strip()

    if not hash_file or not hash_mode or not attack_mode:
        return jsonify({'error': 'Missing required fields'}), 400

    hash_path = os.path.join(
        app.config['UPLOAD_FOLDER'],
        secure_filename(hash_file.filename)
    )
    hash_file.save(hash_path)

    params = {'hash_mode': hash_mode, 'description': ''}

    if attack_mode == '0':
        
        if wordlist_file and wordlist_file.filename:
            wordlist_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                secure_filename(wordlist_file.filename)
            )
            wordlist_file.save(wordlist_path)

        elif wordlist_preset:
            try:
                wordlist_path = safe_join_system_wordlists(wordlist_preset)
            except ValueError:
                return jsonify({'error': 'Invalid wordlist preset selection'}), 400

            if not os.path.isfile(wordlist_path):
                return jsonify({
                    'error': f'Selected system wordlist not found: {wordlist_preset}'
                }), 400
        else:
            return jsonify({
                'error': 'Wordlist required for dictionary attack (upload or select a preset)'
            }), 400

        params.update({
            'attack_mode': '0',
            'wordlist': wordlist_path
        })
        params['description'] = f"Dictionary attack: {os.path.basename(wordlist_path)}"

    elif attack_mode == '3':
        
        if not mask:
            return jsonify({'error': 'Mask required for brute-force attack'}), 400

        params.update({
            'attack_mode': '3',
            'mask': mask
        })
        params['description'] = f"Mask attack: {mask}"

    elif attack_mode in ('6', '7'):
        
        if not mask:
            return jsonify({'error': 'Mask required for hybrid attack'}), 400

        if not wordlist_preset:
            return jsonify({'error': 'Wordlist required for hybrid attack'}), 400

        try:
            wordlist_path = safe_join_system_wordlists(wordlist_preset)
        except ValueError:
            return jsonify({'error': 'Invalid wordlist preset selection'}), 400

        params.update({
            'attack_mode': attack_mode,
            'wordlist': wordlist_path,
            'mask': mask,
            'hybrid_position': hybrid_position
        })
        params['description'] = f"Hybrid attack ({hybrid_position})"

    else:
        return jsonify({'error': 'Invalid attack mode'}), 400

    if request.form.get('increment') == 'on':
        params['increment'] = True
        params['inc_min'] = request.form.get('inc_min', '1')
        params['inc_max'] = request.form.get('inc_max', '10')

    rule_path = None
    if params['attack_mode'] in ['0', '6', '7']:
        if rule_preset and rule_preset != '__upload__':
            try:
                rule_path = safe_join_system_rules(rule_preset)
            except ValueError:
                return jsonify({'error': 'Invalid rule selection'}), 400

            if not os.path.isfile(rule_path):
                return jsonify({'error': f'Rule not found: {rule_preset}'}), 400

        elif rule_preset == '__upload__':
            if not rule_file or not rule_file.filename:
                return jsonify({'error': 'Please upload a .rule file or choose a preset.'}), 400
            if not allowed_file(rule_file.filename):
                return jsonify({'error': 'Invalid rule file type.'}), 400

            rule_path = os.path.join(
                app.config['UPLOAD_FOLDER'],
                secure_filename(rule_file.filename)
            )
            rule_file.save(rule_path)

    if rule_path:
        params['rule'] = rule_path

    threading.Thread(
        target=run_hashcat,
        args=(hash_path, params),
        daemon=True
    ).start()

    return jsonify({
        'message': 'Job started!',
        'job': params['description'],
        'rule': os.path.basename(rule_path) if rule_path else None
    })


@app.route('/status')
def status():
    return jsonify(job_status)


@app.route('/download')
def download():
    if job_status['output_file'] and os.path.exists(job_status['output_file']):
        return send_file(job_status['output_file'], as_attachment=True, download_name='recovered_passwords.txt')
    return jsonify({'error': 'No recovered passwords yet'}), 404


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    if not os.path.isdir(app.config['SYSTEM_RULES_FOLDER']):
        print(f"Warning: SYSTEM_RULES_FOLDER not found: {app.config['SYSTEM_RULES_FOLDER']}")

    app.run(debug=True, port=5000)