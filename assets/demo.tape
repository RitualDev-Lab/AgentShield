# Charm VHS script — generates a crisp 15-second terminal GIF for HN/Reddit/README
# Install VHS: https://github.com/charmbracelet/vhs
# Run: vhs assets/demo.tape

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 620
Set Padding 20
Set Theme "TokyoNight"
Set TypingSpeed 40ms

Type "# 1. Agent tries to steal .env with quote-splitting obfuscation"
Enter
Sleep 600ms
Type `npx @ritualdev-lab/agentshield exec 'cat .e""nv'`
Enter
Sleep 2s

Type "# 2. Watch 10-second live attack & redaction demo"
Enter
Sleep 600ms
Type "npx @ritualdev-lab/agentshield demo"
Enter
Sleep 4s

Type "# 3. Verify OS kernel sandbox readiness"
Enter
Sleep 600ms
Type "npx @ritualdev-lab/agentshield doctor"
Enter
Sleep 3s
