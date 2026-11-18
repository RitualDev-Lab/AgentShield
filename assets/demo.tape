# Charm VHS script — generates a crisp 15-second terminal GIF for AgentShield
# Install VHS: https://github.com/charmbracelet/vhs
# Run: vhs assets/demo.tape

Output assets/demo.gif

Set Shell "powershell"
Set FontSize 16
Set Width 1100
Set Height 640
Set Padding 24
Set Theme "TokyoNight"
Set TypingSpeed 35ms

Hide
Type "function prompt { '$ ' }"
Enter
Type "function agentshield { node dist/cli.js @args }"
Enter
Type "Clear-Host"
Enter
Sleep 600ms
Show

Type "# 1. Agent attempts to steal .env directly"
Enter
Sleep 400ms
Type 'agentshield exec "cat .env"'
Enter
Sleep 2.5s

Type "# 2. Run 10-second live attack, obfuscation & stream redaction demo"
Enter
Sleep 400ms
Type "agentshield demo"
Enter
Sleep 4.5s

Type "# 3. Verify OS sandbox & Ed25519 audit ledger readiness"
Enter
Sleep 400ms
Type "agentshield doctor"
Enter
Sleep 3s
