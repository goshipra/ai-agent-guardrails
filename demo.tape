Output demo.gif

Set FontSize 16
Set Width 1000
Set Height 500
Set Theme "Dracula"
Set Padding 20
Set TypingSpeed 60ms

Hide
Type "source .venv/bin/activate && clear"
Enter
Sleep 500ms
Show

Type "pip install ai-agent-guardrails"
Sleep 800ms
Enter
Sleep 1s

Type `guard check "terraform destroy"`
Sleep 600ms
Enter
Sleep 2500ms

Type `guard check "git push --force origin main"`
Sleep 600ms
Enter
Sleep 2500ms

Type `guard check "npm install"`
Sleep 600ms
Enter
Sleep 2500ms
