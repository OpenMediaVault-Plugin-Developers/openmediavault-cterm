#!/usr/bin/env python3

# Copyright (c) 2025 openmediavault plugin developers
#
# This file is licensed under the terms of the GNU General Public
# License version 2. This program is licensed "as is" without any
# warranty of any kind, whether express or implied.
#
# version: 1.3.1
# Modernized version with improved structure, logging, and performance

import os
import sys
import signal
import logging
import threading
import subprocess
import shutil
import pwd
import grp
import pty
import fcntl
import struct
import termios
import tty
import json
from typing import Dict, Tuple, Optional, List, Any
from pathlib import Path

from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_socketio import SocketIO, emit
import configparser
import PAM
from dataclasses import dataclass

# Constants
CONFIG_FILE = "/etc/omv_cterm.conf"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
ALLOWED_GROUP = "cterm"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
TRANSLATIONS_DIR = Path(__file__).parent / 'translations'
SUPPORTED_LANGUAGES = ['en', 'pl', 'de']  # Add more as needed
DEFAULT_LANGUAGE = 'en'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler("/var/log/omv_cterm.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration dataclass
@dataclass
class ServerConfig:
    host: str
    port: int
    use_https: bool
    ssl_cert: Optional[str]
    ssl_key: Optional[str]
    host_shell: bool

def load_config() -> ServerConfig:
    """Load and validate configuration from file"""
    cfg = configparser.ConfigParser()
    
    # Set defaults
    cfg["server"] = {
        "host": DEFAULT_HOST,
        "port": str(DEFAULT_PORT),
        "use_https": "false",
        "ssl_cert": "",
        "ssl_key": "",
        "host_shell": "false"
    }
    
    try:
        cfg.read(CONFIG_FILE)
    except Exception as e:
        logger.error(f"Failed to read config file: {e}")
    
    srv = cfg["server"]
    
    try:
        return ServerConfig(
            host=srv.get("host", DEFAULT_HOST),
            port=srv.getint("port", DEFAULT_PORT),
            use_https=srv.getboolean("use_https", False),
            ssl_cert=srv.get("ssl_cert") or None,
            ssl_key=srv.get("ssl_key") or None,
            host_shell=srv.getboolean("host_shell", False)
        )
    except ValueError as e:
        logger.error(f"Invalid configuration: {e}")
        sys.exit(1)

# Load configuration
config = load_config()

# Initialize Flask and SocketIO
app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = config.use_https
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hour

# Reduce logging for dependencies
for log_name in ['werkzeug', 'engineio', 'socketio']:
    logging.getLogger(log_name).setLevel(logging.WARNING)

socketio = SocketIO(
    app, 
    async_mode='threading',
    logger=logger.getEffectiveLevel() <= logging.DEBUG,
    engineio_logger=logger.getEffectiveLevel() <= logging.DEBUG
)

# Active shell sessions {sid: (master_fd, child_pid)}
shells: Dict[str, Tuple[int, int]] = {}

# Load translations
translations = {}

def load_translations():
    """Load translations from JSON files"""
    global translations
    for lang in SUPPORTED_LANGUAGES:
        try:
            with open(TRANSLATIONS_DIR / f'{lang}.json', 'r', encoding='utf-8') as f:
                translations[lang] = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load {lang} translations: {e}")
            translations[lang] = {}

load_translations()

def get_translation(key: str, lang: str = None) -> str:
    """Get translation for a key in specified language"""
    if lang is None:
        lang = session.get('language', DEFAULT_LANGUAGE)
    return translations.get(lang, {}).get(key, key)

@app.context_processor
def inject_translations():
    """Make translation function available in all templates"""
    lang = session.get('language', DEFAULT_LANGUAGE)
    language_names = {
        'en': 'English',
        'pl': 'Polski',
        'de': 'Deutsch'
    }
    return {
        '_': lambda x: translations.get(lang, {}).get(x, x),
        'available_languages': SUPPORTED_LANGUAGES,
        'current_language': lang,
        'language_names': language_names
    }

@app.route('/set_language', methods=['POST'])
def set_language():
    """Set language preference"""
    if request.method == 'POST':
        lang = request.json.get('language', DEFAULT_LANGUAGE)
        if lang in SUPPORTED_LANGUAGES:
            session['language'] = lang
            return jsonify({'success': True})
    return jsonify({'success': False}), 400

def handle_sigterm(signum, frame):
    """Cleanup handler for SIGTERM"""
    logger.info("Received SIGTERM, cleaning up...")
    for term_id, (master_fd, pid) in list(shells.items()):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            logger.debug(f"Failed to kill process {pid}: {e}")
        try:
            os.close(master_fd)
        except OSError as e:
            logger.debug(f"Failed to close fd {master_fd}: {e}")
        socketio.emit('terminal_exit', {}, room=term_id)
    shells.clear()
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_sigterm)

def is_user_in_group(username: str, groupname: str) -> bool:
    """Check if user is in specified group"""
    try:
        group = grp.getgrnam(groupname)
        user = pwd.getpwnam(username)
        return username in group.gr_mem or user.pw_gid == group.gr_gid
    except Exception as e:
        logger.error(f"Group check failed for {username}: {e}")
        return False

def pam_authenticate(username: str, password: str) -> bool:
    """Authenticate user via PAM"""
    def pam_conv(auth, query_list, user_data):
        resp = []
        for query, q_type in query_list:
            if q_type in (PAM.PAM_PROMPT_ECHO_ON, PAM.PAM_PROMPT_ECHO_OFF):
                resp.append((password, 0))
            else:
                resp.append(("", 0))
        return resp
    
    try:
        pam = PAM.pam()
        pam.start("other")
        pam.set_item(PAM.PAM_USER, username)
        pam.set_item(PAM.PAM_CONV, pam_conv)
        pam.authenticate()
        pam.acct_mgmt()
        return True
    except Exception as e:
        logger.warning(f"PAM authentication failed for {username}: {e}")
        return False

def get_docker_containers() -> List[Dict[str, str]]:
    """Get list of running Docker containers"""
    try:
        result = subprocess.run(
            ["docker", "container", "ls", "--format", "{{.Names}}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        containers = [name.strip() for name in result.stdout.splitlines() if name.strip()]
        return [{"name": name, "type": "docker"} for name in sorted(containers)]
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get Docker containers: {e.stderr}")
        return []
    except FileNotFoundError:
        logger.debug("Docker not found on system")
        return []

def get_lxc_containers() -> List[Dict[str, str]]:
    """Get list of running LXC containers"""
    if not shutil.which("virsh"):
        return []
    
    try:
        result = subprocess.run(
            ["virsh", "-c", "lxc:///", "list", "--state-running", "--name"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        containers = [name.strip() for name in result.stdout.splitlines() if name.strip()]
        return [{"name": name, "type": "lxc"} for name in sorted(containers)]
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get LXC containers: {e.stderr}")
        return []

def get_containers() -> List[Dict[str, str]]:
    """Get combined list of all available containers"""
    containers = []
    containers.extend(get_docker_containers())
    containers.extend(get_lxc_containers())
    return containers

def is_lxc_container(container_name: str) -> bool:
    """Check if container is an LXC container"""
    if not shutil.which("virsh"):
        return False
    
    try:
        subprocess.run(
            ["virsh", "-c", "lxc:///", "dominfo", container_name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False

def is_docker_container(container_name: str) -> bool:
    """Check if container is a Docker container"""
    try:
        subprocess.run(
            ["docker", "inspect", container_name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False

# Disable caching on all responses
@app.after_request
def after_request(response):
    """Add headers to disable caching"""
    response.headers.update({
        'Cache-Control': 'no-cache, no-store, must-revalidate, public, max-age=0',
        'Pragma': 'no-cache',
        'Expires': '0',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY'
    })
    return response

@app.route('/')
def index():
    """Main entry point with container selection"""
    container = request.args.get('container')
    container_type = request.args.get('container_type')
    
    if session.get('username'):
        if container and container != 'None':
            if container_type and container_type != 'None':
                return redirect(url_for(
                    'terminal', 
                    container=container, 
                    container_type=container_type, 
                    host_shell=config.host_shell
                ))
            return redirect(url_for('terminal', container=container, host_shell=config.host_shell))
        return redirect(url_for('container_selection'))
    
    return render_template(
        'login.html', 
        container=container, 
        container_type=container_type
    )

@app.route('/login', methods=['POST'])
def login():
    """Handle user login"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    container = request.form.get('container')
    container_type = request.form.get('container_type')
    lang = session.get('language', DEFAULT_LANGUAGE)
    
    if not username or not password:
        return render_template(
            'login.html', 
            error=get_translation('required_error', lang),
            container=container,
            container_type=container_type
        )
    
    if not pam_authenticate(username, password):
        logger.warning(f"Failed login attempt for user: {username}")
        return render_template(
            'login.html', 
            error=get_translation('auth_error', lang),
            container=container,
            container_type=container_type
        )
    
    if not is_user_in_group(username, ALLOWED_GROUP):
        logger.warning(f"User {username} not in required group {ALLOWED_GROUP}")
        return render_template(
            'login.html', 
            error=get_translation('group_error', lang).format(group=ALLOWED_GROUP),
            container=container,
            container_type=container_type
        )
    
    session['username'] = username
    logger.info(f"User {username} logged in successfully")
    
    container = request.form.get('container') or request.args.get('container')
    container_type = request.form.get('container_type') or request.args.get('container_type')

    if container and container != 'None':
        if container_type and container_type != 'None':
            return redirect(url_for(
                'terminal', 
                container=container, 
                container_type=container_type
            ))
        return redirect(url_for('terminal', container=container))
    
    return redirect(url_for('container_selection'))

@app.route('/logout')
def logout():
    """Handle user logout"""
    username = session.get('username', 'unknown')
    session.clear()
    logger.info(f"User {username} logged out")
    return redirect(url_for('index'))

@app.route('/containers')
def container_selection():
    """Show container selection page"""
    if not session.get('username'):
        return redirect(url_for('index'))
    
    return render_template(
        'containers.html', 
        containers=get_containers(), 
        host_shell=config.host_shell
    )

@app.route('/terminal/<container>')
@app.route('/terminal/<container>/<container_type>')
def terminal(container: str, container_type: Optional[str] = None):
    """Terminal page handler"""
    if not session.get('username'):
        return redirect(url_for('index', container=container, container_type=container_type))
    
    if container == '__host__':
        if not config.host_shell:
            return render_template(
                'containers.html',
                error=get_translation('host_shell_disabled', session.get('language', DEFAULT_LANGUAGE)),
                containers=get_containers(),
                host_shell=config.host_shell
            )
        return render_template(
            'terminal.html', 
            container='__host__', 
            container_type='host', 
            host_shell=config.host_shell
        )

    if container_type and container_type != 'None':
        if container_type == 'docker' and not is_docker_container(container):
            return render_template(
                'containers.html',
                error=get_translation('docker_not_found', session.get('language', DEFAULT_LANGUAGE)).format(container=container),
                containers=get_containers(),
                host_shell=config.host_shell
            )
        if container_type == 'lxc' and not is_lxc_container(container):
            return render_template(
                'containers.html',
                error=get_translation('lxc_not_found', session.get('language', DEFAULT_LANGUAGE)).format(container=container),
                containers=get_containers(),
                host_shell=config.host_shell
            )
        return render_template(
            'terminal.html', 
            container=container, 
            container_type=container_type, 
            host_shell=config.host_shell
        )

    if is_docker_container(container):
        return render_template(
            'terminal.html', 
            container=container, 
            container_type='docker', 
            host_shell=config.host_shell
        )

    if is_lxc_container(container):
        return render_template(
            'terminal.html', 
            container=container, 
            container_type='lxc', 
            host_shell=config.host_shell
        )

    return render_template(
        'containers.html',
        error=get_translation('container_not_found', session.get('language', DEFAULT_LANGUAGE)).format(container=container),
        containers=get_containers(),
        host_shell=config.host_shell
    )

def read_and_emit(master_fd: int, sid: str):
    """Read from PTY and emit output to client"""
    while True:
        try:
            data = os.read(master_fd, 1024)
            if not data:
                break
            socketio.emit('output', data.decode(errors='ignore'), room=sid)
        except (OSError, UnicodeDecodeError) as e:
            logger.debug(f"PTY read error for session {sid}: {e}")
            break

    # Cleanup when shell exits
    socketio.emit('terminal_exit', {}, room=sid)
    try:
        os.close(master_fd)
    except OSError as e:
        logger.debug(f"Failed to close master_fd for session {sid}: {e}")
    shells.pop(sid, None)
    logger.info(f"Terminal session ended for {sid}")

@socketio.on('connect')
def on_connect():
    """Handle new client connection"""
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    """Handle client disconnection"""
    sid = request.sid
    entry = shells.pop(sid, None)
    if entry:
        master_fd, pid = entry
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            logger.debug(f"Failed to kill process {pid}: {e}")
        try:
            os.close(master_fd)
        except OSError as e:
            logger.debug(f"Failed to close fd {master_fd}: {e}")
    logger.info(f"Client disconnected: {sid}")

@socketio.on('start_terminal')
def start_terminal(data: Dict[str, Any]):
    """Start a new terminal session"""
    container = data.get('container')
    container_type = data.get('container_type', 'docker')
    sid = request.sid
    
    if container == '__host__':
        if not config.host_shell:
            emit('output', get_translation('host_shell_disabled', session.get('language', DEFAULT_LANGUAGE)) + '\n')
            return
    
    if not container:
        emit('output', get_translation('no_container_specified', session.get('language', DEFAULT_LANGUAGE)) + '\n')
        return
    
    if sid in shells:
        emit('output', f'[{container}]$ ')
        return
    
    try:
        pid, master_fd = pty.fork()
    except OSError as e:
        logger.error(f"Failed to fork PTY: {e}")
        emit('output', get_translation('terminal_create_failed', session.get('language', DEFAULT_LANGUAGE)) + '\n')
        return
    
    if pid == 0:  # Child process
        try:
            env = os.environ.copy()
            env['TERM'] = data.get('termType', 'xterm')
            
            if container == '__host__':
                username = session.get('username')
                if not username:
                    os._exit(1)
                
                pw = pwd.getpwnam(username)
                os.setgid(pw.pw_gid)
                os.setuid(pw.pw_uid)
                
                home_dir = pw.pw_dir if os.path.isdir(pw.pw_dir) else '/tmp'
                os.chdir(home_dir)
                
                env.update({
                    'HOME': pw.pw_dir,
                    'PWD': home_dir,
                    'USER': username,
                    'LOGNAME': username
                })
                env.pop('MAIL', None)
                
                args = ['--login', '-i']
                os.execvpe('bash', args, env)
            
            elif container_type == 'lxc':
                args = ['virsh', '-c', 'lxc:///', 'console', container]
                os.execvpe('virsh', args, env)
            
            else:  # Docker
                base_args = ['docker', 'exec', '-i', '-t', container]
                
                # Check for bash availability
                check = subprocess.call(
                    base_args + ['bash', '-c', 'exit 0'],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                shell_args = ['bash', '--noprofile', '--norc', '-i'] if check == 0 else ['sh', '-i']
                os.execvpe('docker', base_args + shell_args, env)
        
        except Exception as e:
            logger.error(f"Failed to start shell: {e}")
            os._exit(1)
    
    else:  # Parent process
        try:
            tty.setraw(master_fd)
            if container == '__host__':
                attrs = termios.tcgetattr(master_fd)
                attrs[3] |= termios.ECHO
                attrs[1] |= termios.OPOST | termios.ONLCR
                termios.tcsetattr(master_fd, termios.TCSADRAIN, attrs)
            
            shells[sid] = (master_fd, pid)
            threading.Thread(
                target=read_and_emit,
                args=(master_fd, sid),
                daemon=True
            ).start()
            
            welcome_msg = (
                get_translation('connected_lxc', session.get('language', DEFAULT_LANGUAGE)).format(container=container) + '\r\n' 
                if container_type == 'lxc'
                else get_translation('connected_docker', session.get('language', DEFAULT_LANGUAGE)).format(container=container) + '\r\n'
            )
            emit('output', welcome_msg)
            logger.info(f"Started terminal session for {container} ({container_type})")
        
        except Exception as e:
            logger.error(f"Failed to setup terminal: {e}")
            try:
                os.kill(pid, signal.SIGTERM)
                os.close(master_fd)
            except OSError:
                pass
            emit('output', get_translation('terminal_init_failed', session.get('language', DEFAULT_LANGUAGE)) + '\n')

@socketio.on('terminal_input')
def terminal_input(data: Dict[str, str]):
    """Handle terminal input from client"""
    sid = request.sid
    inp = data.get('input', '')
    
    if not inp:
        return
    
    entry = shells.get(sid)
    if entry:
        try:
            master_fd, _ = entry
            os.write(master_fd, inp.encode())
        except OSError as e:
            logger.debug(f"Failed to write to PTY for {sid}: {e}")
    else:
        emit('output', get_translation('no_shell_session', session.get('language', DEFAULT_LANGUAGE)) + '\n')

@socketio.on('resize')
def resize(data: Dict[str, int]):
    """Handle terminal resize"""
    sid = request.sid
    entry = shells.get(sid)
    
    if not entry:
        return
    
    try:
        master_fd, child_pid = entry
        rows, cols = data['rows'], data['cols']
        winsize = struct.pack('HHHH', rows, cols, 0, 0)
        fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
        os.kill(child_pid, signal.SIGWINCH)
    except (OSError, KeyError) as e:
        logger.debug(f"Failed to resize terminal for {sid}: {e}")

@socketio.on('close_terminal')
def on_close_terminal(data: Dict[str, Any]):
    """Close terminal session"""
    sid = request.sid
    entry = shells.pop(sid, None)
    
    if entry:
        master_fd, child_pid = entry
        try:
            os.kill(child_pid, signal.SIGTERM)
        except OSError as e:
            logger.debug(f"Failed to kill process {child_pid}: {e}")
        try:
            os.close(master_fd)
        except OSError as e:
            logger.debug(f"Failed to close fd {master_fd}: {e}")
        logger.info(f"Terminal session closed by client: {sid}")

if __name__ == '__main__':
    try:
        logger.info(f"Starting server on {config.host}:{config.port}")
        
        run_kwargs = {
            'host': config.host,
            'port': config.port,
            'allow_unsafe_werkzeug': True, # Only for development!
            'log_output': False
        }
        
        if config.use_https and config.ssl_cert and config.ssl_key:
            if not Path(config.ssl_cert).is_file() or not Path(config.ssl_key).is_file():
                logger.error("SSL certificate or key file not found")
                sys.exit(1)
            run_kwargs['ssl_context'] = (config.ssl_cert, config.ssl_key)
        
        socketio.run(app, **run_kwargs)
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)
