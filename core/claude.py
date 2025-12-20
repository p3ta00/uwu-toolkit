"""
Claude AI Integration for UwU Toolkit
Provides code analysis, vulnerability scanning, and debugging assistance
"""

import os
import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from .colors import Colors, Style


class ClaudeSession:
    """Represents a single Claude conversation session"""

    def __init__(self, session_id: str = None, name: str = None, system_prompt: str = None):
        self.id = session_id or str(uuid.uuid4())[:8]
        self.name = name or f"session-{self.id}"
        self.created_at = datetime.now()
        self.messages: List[Dict[str, str]] = []
        self.system_prompt = system_prompt or self._default_system_prompt()
        self.context_files: List[str] = []  # Files loaded into context

    def _default_system_prompt(self) -> str:
        return """You are Claude, an AI assistant integrated into UwU Toolkit - a penetration testing framework.
You help security professionals with:
- Code analysis and vulnerability assessment
- Debugging and fixing code issues
- Explaining security concepts and attack techniques
- Writing exploits, scripts, and security tools
- Analyzing captured data and network traffic

Be direct, technical, and practical. Provide actionable information.
When analyzing code, include specific line numbers and concrete examples.
Format code blocks with appropriate language tags."""

    def add_message(self, role: str, content: str) -> None:
        """Add a message to the conversation history"""
        self.messages.append({"role": role, "content": content})

    def get_messages(self) -> List[Dict[str, str]]:
        """Get all messages for API call"""
        return self.messages.copy()

    def clear(self) -> None:
        """Clear conversation history"""
        self.messages = []
        self.context_files = []

    def get_summary(self) -> str:
        """Get a brief summary of this session"""
        msg_count = len(self.messages)
        user_msgs = sum(1 for m in self.messages if m["role"] == "user")
        return f"{self.name} ({user_msgs} prompts, {msg_count} total messages)"


class ClaudeSessionManager:
    """Manages multiple Claude sessions"""

    def __init__(self):
        self.sessions: Dict[str, ClaudeSession] = {}
        self.active_session_id: Optional[str] = None

    def create_session(self, name: str = None, system_prompt: str = None) -> ClaudeSession:
        """Create a new session"""
        session = ClaudeSession(name=name, system_prompt=system_prompt)
        self.sessions[session.id] = session
        self.active_session_id = session.id
        return session

    def get_active_session(self) -> Optional[ClaudeSession]:
        """Get the currently active session"""
        if self.active_session_id and self.active_session_id in self.sessions:
            return self.sessions[self.active_session_id]
        return None

    def switch_session(self, session_id: str) -> Optional[ClaudeSession]:
        """Switch to a different session"""
        if session_id in self.sessions:
            self.active_session_id = session_id
            return self.sessions[session_id]
        # Try matching by name or partial ID
        for sid, session in self.sessions.items():
            if session.name == session_id or sid.startswith(session_id):
                self.active_session_id = sid
                return session
        return None

    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        for sid in list(self.sessions.keys()):
            if sid == session_id or self.sessions[sid].name == session_id or sid.startswith(session_id):
                del self.sessions[sid]
                if self.active_session_id == sid:
                    self.active_session_id = next(iter(self.sessions.keys()), None)
                return True
        return False

    def list_sessions(self) -> List[ClaudeSession]:
        """List all sessions"""
        return list(self.sessions.values())


class ClaudeMode:
    """Interactive Claude mode handler"""

    def __init__(self, assistant: "ClaudeAssistant", config=None):
        self.assistant = assistant
        self.config = config
        self.session_manager = ClaudeSessionManager()
        self.running = False
        self.backgrounded = False

    def get_prompt(self) -> str:
        """Generate the Claude mode prompt"""
        session = self.session_manager.get_active_session()
        if session:
            session_name = session.name[:15]
            msg_count = len(session.messages)
            return f"{Colors.NEON_PURPLE}claude{Colors.RESET}({Colors.NEON_CYAN}{session_name}{Colors.RESET})[{msg_count}] > "
        return f"{Colors.NEON_PURPLE}claude{Colors.RESET} > "

    def start(self) -> None:
        """Start interactive Claude mode"""
        available, msg = self.assistant.is_available()
        if not available:
            print(Style.error(msg))
            return

        self.running = True
        self.backgrounded = False

        # Create initial session if none exists
        if not self.session_manager.get_active_session():
            self.session_manager.create_session("main")

        print()
        print(f"  {Colors.NEON_PURPLE}╔══════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"  {Colors.NEON_PURPLE}║{Colors.RESET}  {Colors.NEON_PINK}Claude Interactive Mode{Colors.RESET}                             {Colors.NEON_PURPLE}║{Colors.RESET}")
        print(f"  {Colors.NEON_PURPLE}║{Colors.RESET}  Type your message and press Enter to chat            {Colors.NEON_PURPLE}║{Colors.RESET}")
        print(f"  {Colors.NEON_PURPLE}║{Colors.RESET}  {Colors.NEON_CYAN}Ctrl+D{Colors.RESET} - Background and return to UwU              {Colors.NEON_PURPLE}║{Colors.RESET}")
        print(f"  {Colors.NEON_PURPLE}║{Colors.RESET}  {Colors.NEON_CYAN}/help{Colors.RESET}  - Show Claude mode commands                 {Colors.NEON_PURPLE}║{Colors.RESET}")
        print(f"  {Colors.NEON_PURPLE}║{Colors.RESET}  {Colors.NEON_CYAN}/exit{Colors.RESET}  - Exit Claude mode                          {Colors.NEON_PURPLE}║{Colors.RESET}")
        print(f"  {Colors.NEON_PURPLE}╚══════════════════════════════════════════════════════╝{Colors.RESET}")
        print()

        self._run_loop()

    def resume(self) -> None:
        """Resume a backgrounded Claude session"""
        if not self.session_manager.sessions:
            print(Style.warning("No Claude sessions to resume"))
            return

        self.running = True
        self.backgrounded = False

        session = self.session_manager.get_active_session()
        print()
        print(Style.success(f"Resumed Claude session: {session.name}"))
        print(Style.dim(f"  {len(session.messages)} messages in history"))
        print()

        self._run_loop()

    def _run_loop(self) -> None:
        """Main interactive loop"""
        while self.running and not self.backgrounded:
            try:
                user_input = input(self.get_prompt()).strip()

                if not user_input:
                    continue

                # Handle slash commands
                if user_input.startswith("/"):
                    self._handle_command(user_input)
                else:
                    self._send_message(user_input)

            except EOFError:
                # Ctrl+D pressed - background the session
                print()
                self._background()
            except KeyboardInterrupt:
                print()
                print(Style.info("Use /exit to quit or Ctrl+D to background"))

    def _background(self) -> None:
        """Background Claude mode and return to UwU"""
        self.backgrounded = True
        session = self.session_manager.get_active_session()
        print(Style.info(f"Claude session '{session.name}' backgrounded"))
        print(Style.dim("  Use 'claude resume' or 'claude fg' to return"))

    def _handle_command(self, cmd: str) -> None:
        """Handle slash commands in Claude mode"""
        parts = cmd[1:].split(None, 1)
        command = parts[0].lower() if parts else ""
        args = parts[1] if len(parts) > 1 else ""

        if command in ("exit", "quit", "q"):
            self.running = False
            print(Style.info("Exiting Claude mode"))

        elif command in ("bg", "background"):
            self._background()

        elif command in ("help", "h", "?"):
            self._show_help()

        elif command == "clear":
            session = self.session_manager.get_active_session()
            if session:
                session.clear()
                print(Style.success("Conversation cleared"))

        elif command == "new":
            name = args if args else None
            session = self.session_manager.create_session(name=name)
            print(Style.success(f"Created new session: {session.name}"))

        elif command in ("sessions", "list", "ls"):
            self._list_sessions()

        elif command in ("switch", "sw"):
            if not args:
                print(Style.error("Usage: /switch <session_name_or_id>"))
                return
            session = self.session_manager.switch_session(args)
            if session:
                print(Style.success(f"Switched to session: {session.name}"))
            else:
                print(Style.error(f"Session not found: {args}"))

        elif command in ("delete", "del", "rm"):
            if not args:
                print(Style.error("Usage: /delete <session_name_or_id>"))
                return
            if self.session_manager.delete_session(args):
                print(Style.success(f"Deleted session: {args}"))
            else:
                print(Style.error(f"Session not found: {args}"))

        elif command == "rename":
            if not args:
                print(Style.error("Usage: /rename <new_name>"))
                return
            session = self.session_manager.get_active_session()
            if session:
                old_name = session.name
                session.name = args
                print(Style.success(f"Renamed '{old_name}' to '{args}'"))

        elif command == "context":
            self._show_context()

        elif command == "load":
            if not args:
                print(Style.error("Usage: /load <file_or_directory>"))
                return
            self._load_context(args)

        elif command == "model":
            if args:
                self.assistant.set_model(args)
            else:
                print(Style.info(f"Current model: {self.assistant.model}"))

        elif command == "system":
            if args:
                session = self.session_manager.get_active_session()
                if session:
                    session.system_prompt = args
                    print(Style.success("System prompt updated"))
            else:
                session = self.session_manager.get_active_session()
                if session:
                    print(f"\n{Style.highlight('Current System Prompt')}")
                    print(f"{Colors.GRID}{'-'*50}{Colors.RESET}")
                    print(session.system_prompt)
                    print()

        elif command == "history":
            self._show_history()

        elif command == "analyze":
            if not args:
                print(Style.error("Usage: /analyze <path> [--focus <area>]"))
                return
            # Parse and run analysis
            arg_parts = args.split()
            paths = []
            focus = None
            i = 0
            while i < len(arg_parts):
                if arg_parts[i] == "--focus" and i + 1 < len(arg_parts):
                    focus = arg_parts[i + 1]
                    i += 2
                else:
                    paths.append(arg_parts[i])
                    i += 1
            if paths:
                result = self.assistant.analyze_vulnerabilities(paths, focus)
                print(result)

        elif command == "debug":
            if not args:
                print(Style.error("Usage: /debug <path> [--error \"message\"]"))
                return
            arg_parts = args.split()
            paths = []
            error_msg = None
            i = 0
            while i < len(arg_parts):
                if arg_parts[i] == "--error" and i + 1 < len(arg_parts):
                    error_msg = arg_parts[i + 1]
                    i += 2
                else:
                    paths.append(arg_parts[i])
                    i += 1
            if paths:
                result = self.assistant.debug_code(paths, error_msg)
                print(result)

        else:
            print(Style.error(f"Unknown command: /{command}"))
            print(Style.info("Type /help for available commands"))

    def _show_help(self) -> None:
        """Show help for Claude mode"""
        print(f"""
{Colors.NEON_PURPLE}Claude Mode Commands{Colors.RESET}
{Colors.NEON_PURPLE}===================={Colors.RESET}

{Colors.NEON_CYAN}Navigation{Colors.RESET}
  {Colors.NEON_GREEN}Ctrl+D{Colors.RESET}              Background Claude, return to UwU
  {Colors.NEON_GREEN}/exit, /quit{Colors.RESET}        Exit Claude mode completely
  {Colors.NEON_GREEN}/bg{Colors.RESET}                 Background Claude session

{Colors.NEON_CYAN}Sessions{Colors.RESET}
  {Colors.NEON_GREEN}/new [name]{Colors.RESET}         Create new session
  {Colors.NEON_GREEN}/sessions{Colors.RESET}           List all sessions
  {Colors.NEON_GREEN}/switch <id>{Colors.RESET}        Switch to another session
  {Colors.NEON_GREEN}/delete <id>{Colors.RESET}        Delete a session
  {Colors.NEON_GREEN}/rename <name>{Colors.RESET}      Rename current session
  {Colors.NEON_GREEN}/clear{Colors.RESET}              Clear conversation history

{Colors.NEON_CYAN}Context{Colors.RESET}
  {Colors.NEON_GREEN}/load <path>{Colors.RESET}        Load file/directory into context
  {Colors.NEON_GREEN}/context{Colors.RESET}            Show loaded context files
  {Colors.NEON_GREEN}/system [prompt]{Colors.RESET}    View/set system prompt

{Colors.NEON_CYAN}Analysis{Colors.RESET}
  {Colors.NEON_GREEN}/analyze <path>{Colors.RESET}     Run vulnerability analysis
  {Colors.NEON_GREEN}/debug <path>{Colors.RESET}       Debug code for errors

{Colors.NEON_CYAN}Settings{Colors.RESET}
  {Colors.NEON_GREEN}/model [name]{Colors.RESET}       View/set Claude model
  {Colors.NEON_GREEN}/history{Colors.RESET}            Show conversation history
  {Colors.NEON_GREEN}/help{Colors.RESET}               Show this help
""")

    def _list_sessions(self) -> None:
        """List all Claude sessions"""
        sessions = self.session_manager.list_sessions()
        if not sessions:
            print(Style.warning("No sessions"))
            return

        active = self.session_manager.get_active_session()
        print(f"\n  {Style.highlight('Claude Sessions')}")
        print(f"  {Colors.NEON_PINK}{'='*50}{Colors.RESET}\n")

        for session in sessions:
            marker = f"{Colors.NEON_GREEN}*{Colors.RESET}" if session == active else " "
            msg_count = len(session.messages)
            user_msgs = sum(1 for m in session.messages if m["role"] == "user")
            created = session.created_at.strftime("%H:%M:%S")
            print(f"  {marker} {Colors.NEON_CYAN}{session.id}{Colors.RESET}  {session.name}")
            print(f"      {Colors.GRID}{user_msgs} prompts, created {created}{Colors.RESET}")
        print()

    def _show_context(self) -> None:
        """Show loaded context files"""
        session = self.session_manager.get_active_session()
        if not session or not session.context_files:
            print(Style.warning("No context files loaded"))
            return

        print(f"\n  {Style.highlight('Loaded Context Files')}")
        print(f"  {Colors.NEON_PINK}{'='*50}{Colors.RESET}\n")
        for f in session.context_files:
            print(f"    {Colors.NEON_CYAN}{f}{Colors.RESET}")
        print()

    def _load_context(self, path: str) -> None:
        """Load file(s) into context"""
        session = self.session_manager.get_active_session()
        if not session:
            return

        content, errors = self.assistant._read_files([path])
        if errors:
            for err in errors:
                print(Style.warning(f"Skipped: {err}"))

        if content.strip():
            # Add as a context message
            context_msg = f"I'm loading the following code into our context for reference:\n\n{content}"
            session.add_message("user", context_msg)
            session.add_message("assistant", "I've received the code context. I'll reference it in our conversation. What would you like to know about it?")
            session.context_files.append(path)
            print(Style.success(f"Loaded context from: {path}"))
            print(Style.dim(f"  {len(content):,} characters added to context"))
        else:
            print(Style.error("No content found to load"))

    def _show_history(self) -> None:
        """Show conversation history"""
        session = self.session_manager.get_active_session()
        if not session or not session.messages:
            print(Style.warning("No conversation history"))
            return

        print(f"\n  {Style.highlight('Conversation History')}")
        print(f"  {Colors.NEON_PINK}{'='*60}{Colors.RESET}\n")

        for i, msg in enumerate(session.messages):
            role = msg["role"]
            content = msg["content"]
            # Truncate long messages
            if len(content) > 200:
                content = content[:200] + "..."

            if role == "user":
                print(f"  {Colors.NEON_CYAN}[You]{Colors.RESET} {content}")
            else:
                print(f"  {Colors.NEON_PURPLE}[Claude]{Colors.RESET} {content}")
            print()

    def _send_message(self, message: str) -> None:
        """Send a message to Claude"""
        session = self.session_manager.get_active_session()
        if not session:
            print(Style.error("No active session"))
            return

        # Add user message
        session.add_message("user", message)

        print()
        print(Style.dim("Thinking..."))

        try:
            client = self.assistant._get_client()
            response = client.messages.create(
                model=self.assistant.model,
                max_tokens=4096,
                system=session.system_prompt,
                messages=session.get_messages()
            )

            assistant_message = response.content[0].text
            session.add_message("assistant", assistant_message)

            # Clear "Thinking..." and print response
            print(f"\033[A\033[K", end="")  # Move up and clear line
            print(f"\n  {Colors.NEON_PURPLE}Claude:{Colors.RESET}")
            print(f"  {Colors.NEON_PINK}{'─'*60}{Colors.RESET}")

            for line in assistant_message.split('\n'):
                print(f"  {line}")

            print(f"  {Colors.NEON_PINK}{'─'*60}{Colors.RESET}")
            print()

        except Exception as e:
            # Remove the user message since we failed
            session.messages.pop()
            print(f"\033[A\033[K", end="")
            print(Style.error(f"API error: {e}"))
            print()


class ClaudeAssistant:
    """Claude AI integration for code analysis and debugging"""

    # System prompts for different tasks
    VULN_ANALYSIS_PROMPT = """You are a senior security researcher analyzing source code for vulnerabilities.
Your task is to identify security issues in the provided code.

Focus on:
- Injection vulnerabilities (SQL, Command, LDAP, XPath, etc.)
- Authentication/Authorization flaws
- Sensitive data exposure
- Security misconfigurations
- Known vulnerable components
- Insecure deserialization
- Broken access control
- Cryptographic failures
- SSRF, XXE, and other OWASP Top 10 issues

For each vulnerability found:
1. Identify the specific line(s) and code pattern
2. Explain the risk and potential impact
3. Provide a severity rating (Critical/High/Medium/Low/Info)
4. Suggest a fix or mitigation

Be thorough but concise. Focus on actionable findings."""

    DEBUG_PROMPT = """You are an expert programmer and debugger.
Analyze the provided code for syntax errors, logic bugs, and runtime issues.

Focus on:
- Syntax errors and typos
- Logic errors and edge cases
- Type mismatches
- Null/undefined references
- Resource leaks
- Race conditions
- Error handling gaps
- Performance issues

Provide:
1. Identified issues with line numbers
2. Clear explanation of each problem
3. Corrected code snippets where applicable
4. Best practice recommendations"""

    GENERAL_PROMPT = """You are a helpful assistant integrated into UwU Toolkit, a penetration testing framework.
Help the user with their security-related questions about code, tools, or techniques.
Be direct and technical. Focus on practical, actionable information."""

    def __init__(self, config=None):
        self.config = config
        self.client = None
        self.model = "claude-sonnet-4-20250514"  # Default model
        self._api_key: Optional[str] = None

    def _get_api_key(self) -> Optional[str]:
        """Get API key from config or environment"""
        if self._api_key:
            return self._api_key

        # Check environment first
        key = os.environ.get("ANTHROPIC_API_KEY")
        if key:
            self._api_key = key
            return key

        # Check config
        if self.config:
            key = self.config.get("ANTHROPIC_API_KEY")
            if key:
                self._api_key = key
                return key

        return None

    def is_available(self) -> Tuple[bool, str]:
        """Check if Claude integration is available"""
        if not ANTHROPIC_AVAILABLE:
            return False, "anthropic package not installed. Run: pip install anthropic"

        if not self._get_api_key():
            return False, "ANTHROPIC_API_KEY not set. Use: setg ANTHROPIC_API_KEY <key>"

        return True, "Claude integration ready"

    def _get_client(self):
        """Get or create Anthropic client"""
        if self.client is None:
            api_key = self._get_api_key()
            if not api_key:
                raise ValueError("No API key configured")
            self.client = anthropic.Anthropic(api_key=api_key)
        return self.client

    def _read_files(self, paths: List[str]) -> Tuple[str, List[str]]:
        """Read multiple files and return combined content"""
        content_parts = []
        errors = []

        for path in paths:
            p = Path(path).expanduser()
            if p.is_file():
                try:
                    text = p.read_text(errors='replace')
                    content_parts.append(f"=== FILE: {p} ===\n{text}\n")
                except Exception as e:
                    errors.append(f"{p}: {e}")
            elif p.is_dir():
                # Scan directory for common source files
                extensions = {'.py', '.js', '.ts', '.php', '.java', '.c', '.cpp', '.h',
                             '.cs', '.go', '.rb', '.rs', '.ps1', '.sh', '.pl', '.aspx',
                             '.jsp', '.sql', '.xml', '.json', '.yaml', '.yml', '.conf'}
                for file in p.rglob('*'):
                    if file.is_file() and file.suffix.lower() in extensions:
                        try:
                            text = file.read_text(errors='replace')
                            # Skip very large files
                            if len(text) < 100000:
                                content_parts.append(f"=== FILE: {file} ===\n{text}\n")
                        except Exception as e:
                            errors.append(f"{file}: {e}")
            else:
                errors.append(f"{path}: Not found")

        return "\n".join(content_parts), errors

    def analyze_vulnerabilities(self, paths: List[str], focus: Optional[str] = None) -> str:
        """Analyze code for security vulnerabilities"""
        available, msg = self.is_available()
        if not available:
            return Style.error(msg)

        code_content, errors = self._read_files(paths)

        if errors:
            for err in errors:
                print(Style.warning(f"Skipped: {err}"))

        if not code_content.strip():
            return Style.error("No code found to analyze")

        system_prompt = self.VULN_ANALYSIS_PROMPT
        if focus:
            system_prompt += f"\n\nFocus especially on: {focus}"

        user_prompt = f"Analyze the following code for security vulnerabilities:\n\n{code_content}"

        print(Style.info("Analyzing code for vulnerabilities..."))
        print(Style.dim(f"Sending {len(code_content):,} characters to Claude"))
        print()

        try:
            client = self._get_client()
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}]
            )

            return self._format_response(response.content[0].text, "Vulnerability Analysis")

        except Exception as e:
            return Style.error(f"API error: {e}")

    def debug_code(self, paths: List[str], error_msg: Optional[str] = None) -> str:
        """Debug code for syntax errors and issues"""
        available, msg = self.is_available()
        if not available:
            return Style.error(msg)

        code_content, errors = self._read_files(paths)

        if errors:
            for err in errors:
                print(Style.warning(f"Skipped: {err}"))

        if not code_content.strip():
            return Style.error("No code found to debug")

        user_prompt = f"Debug the following code:\n\n{code_content}"
        if error_msg:
            user_prompt += f"\n\nThe user is seeing this error:\n{error_msg}"

        print(Style.info("Analyzing code for issues..."))
        print(Style.dim(f"Sending {len(code_content):,} characters to Claude"))
        print()

        try:
            client = self._get_client()
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.DEBUG_PROMPT,
                messages=[{"role": "user", "content": user_prompt}]
            )

            return self._format_response(response.content[0].text, "Debug Analysis")

        except Exception as e:
            return Style.error(f"API error: {e}")

    def ask(self, question: str, context_paths: Optional[List[str]] = None) -> str:
        """Ask Claude a general question, optionally with code context"""
        available, msg = self.is_available()
        if not available:
            return Style.error(msg)

        user_prompt = question

        if context_paths:
            code_content, errors = self._read_files(context_paths)
            if code_content.strip():
                user_prompt = f"Context code:\n\n{code_content}\n\nQuestion: {question}"
                print(Style.dim(f"Including {len(code_content):,} characters of context"))

        print(Style.info("Asking Claude..."))
        print()

        try:
            client = self._get_client()
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=self.GENERAL_PROMPT,
                messages=[{"role": "user", "content": user_prompt}]
            )

            return self._format_response(response.content[0].text, "Response")

        except Exception as e:
            return Style.error(f"API error: {e}")

    def _format_response(self, text: str, title: str) -> str:
        """Format Claude's response with nice styling"""
        lines = [
            "",
            f"  {Style.highlight(title)}",
            f"  {Colors.NEON_PINK}{'='*60}{Colors.RESET}",
            ""
        ]

        # Add the response text with mild formatting
        for line in text.split('\n'):
            # Highlight severity markers
            if 'CRITICAL' in line.upper():
                line = line.replace('Critical', f'{Colors.NEON_MAGENTA}Critical{Colors.RESET}')
                line = line.replace('CRITICAL', f'{Colors.NEON_MAGENTA}CRITICAL{Colors.RESET}')
            elif 'HIGH' in line.upper() and ('severity' in line.lower() or 'risk' in line.lower() or line.strip().startswith('-')):
                line = line.replace('High', f'{Colors.NEON_ORANGE}High{Colors.RESET}')
                line = line.replace('HIGH', f'{Colors.NEON_ORANGE}HIGH{Colors.RESET}')
            elif 'MEDIUM' in line.upper():
                line = line.replace('Medium', f'{Colors.NEON_YELLOW}Medium{Colors.RESET}')
                line = line.replace('MEDIUM', f'{Colors.NEON_YELLOW}MEDIUM{Colors.RESET}')
            elif 'LOW' in line.upper() and ('severity' in line.lower() or 'risk' in line.lower()):
                line = line.replace('Low', f'{Colors.NEON_CYAN}Low{Colors.RESET}')
                line = line.replace('LOW', f'{Colors.NEON_CYAN}LOW{Colors.RESET}')

            lines.append(f"  {line}")

        lines.append("")
        return '\n'.join(lines)

    def set_model(self, model: str) -> None:
        """Set the Claude model to use"""
        valid_models = [
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
        ]
        if model in valid_models or model.startswith("claude-"):
            self.model = model
            print(Style.success(f"Model set to: {model}"))
        else:
            print(Style.warning(f"Unknown model: {model}"))
            print(Style.info(f"Valid models: {', '.join(valid_models)}"))


def get_claude_help() -> str:
    """Return help text for Claude commands"""
    return f"""
{Colors.NEON_PINK}Claude AI Commands{Colors.RESET}
{Colors.NEON_PINK}=================={Colors.RESET}

{Colors.NEON_PURPLE}Interactive Mode{Colors.RESET}
  {Colors.NEON_CYAN}claude{Colors.RESET} or {Colors.NEON_CYAN}claude mode{Colors.RESET}
      Enter interactive Claude mode (full conversation)
      {Colors.NEON_GREEN}Ctrl+D{Colors.RESET} to background, {Colors.NEON_GREEN}/exit{Colors.RESET} to quit

  {Colors.NEON_CYAN}claude resume{Colors.RESET} or {Colors.NEON_CYAN}claude fg{Colors.RESET}
      Resume backgrounded Claude session

  {Colors.NEON_CYAN}claude sessions{Colors.RESET}
      List all Claude sessions

{Colors.NEON_PURPLE}Quick Commands{Colors.RESET}
  {Colors.NEON_CYAN}claude analyze <path>{Colors.RESET}
      Scan code for security vulnerabilities

  {Colors.NEON_CYAN}claude analyze <path> --focus <area>{Colors.RESET}
      Focus analysis (e.g., "sql injection", "auth")

  {Colors.NEON_CYAN}claude debug <path>{Colors.RESET}
      Debug code for syntax/logic errors

  {Colors.NEON_CYAN}claude debug <path> --error "msg"{Colors.RESET}
      Debug with specific error context

  {Colors.NEON_CYAN}claude ask "question"{Colors.RESET}
      Ask a security-related question

  {Colors.NEON_CYAN}claude ask "question" --context <path>{Colors.RESET}
      Ask with code context

{Colors.NEON_PURPLE}Settings{Colors.RESET}
  {Colors.NEON_CYAN}claude model <name>{Colors.RESET}
      Set Claude model (default: claude-sonnet-4-20250514)

  {Colors.NEON_CYAN}claude status{Colors.RESET}
      Check integration status

{Colors.NEON_PURPLE}Setup{Colors.RESET}
  1. Install: {Colors.NEON_CYAN}pip install anthropic{Colors.RESET}
  2. Set key: {Colors.NEON_CYAN}setg ANTHROPIC_API_KEY sk-ant-...{Colors.RESET}

{Colors.NEON_PURPLE}Interactive Mode Commands{Colors.RESET}
  In Claude mode, type messages directly or use / commands:
  {Colors.NEON_GREEN}/sessions{Colors.RESET}      List sessions     {Colors.NEON_GREEN}/new [name]{Colors.RESET}    Create session
  {Colors.NEON_GREEN}/switch <id>{Colors.RESET}   Switch session    {Colors.NEON_GREEN}/delete <id>{Colors.RESET}   Delete session
  {Colors.NEON_GREEN}/load <path>{Colors.RESET}   Load code context {Colors.NEON_GREEN}/clear{Colors.RESET}         Clear history
  {Colors.NEON_GREEN}/analyze{Colors.RESET}       Run vuln scan     {Colors.NEON_GREEN}/debug{Colors.RESET}         Debug code
  {Colors.NEON_GREEN}/history{Colors.RESET}       Show history      {Colors.NEON_GREEN}/help{Colors.RESET}          Full help

{Colors.NEON_PURPLE}Examples{Colors.RESET}
  {Colors.DIGITAL_RAIN}claude{Colors.RESET}
      Enter interactive mode for conversation

  {Colors.DIGITAL_RAIN}claude analyze /tmp/webapp/{Colors.RESET}
      Quick vulnerability scan

  {Colors.DIGITAL_RAIN}claude ask "how do I exploit SSRF"{Colors.RESET}
      Quick question
"""
