# 179ssoma


These are all the original code for packet sniffing I wrote before I used scp to port them over to my openwrt router and then make further edits there. anomaly.py was the python script I was working on and running directly at root. The SMTP does not work. 

My demo used a modified form of anomaly.py without a sliding window, just rejecting attempts from a specific address past the threshold number of attempts. 

The screen recording is the demo I included in my presentation, and the demo.mp4 is the setup process I shared via email. 

The dockerfile works fine but I chose not to use it because of concerns regarding space constraints. 
