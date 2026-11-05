# Records docs/demo.gif with vhs (https://github.com/charmbracelet/vhs). See
# docs/demo/README.md for the cluster it scans.
Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1240
Set Height 830
Set Padding 24
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Hide
Type "export PATH=$PWD/bin:$PATH PS1='$ ' && clear"
Enter
Show

Sleep 500ms
Type "certlapse scan --kube-context staging -n demo"
Sleep 600ms
Enter
Sleep 9s
