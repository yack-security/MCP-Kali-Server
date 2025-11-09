# MCP Kali Server

## Yack Fork

- Added `requirements.txt` file.
- Added `--ip` argument to the `kali_server.py` script to set the IP address of the server.
- Added `env.txt` example file to set the environment variables for the server.
- Added `kali-mcp-server-service.txt` example file to set the service for the MCP server.
- Added Cloudflare Zero Trust support (Headers for service authentication).

Environment variables:

```bash
cp env.txt .env
# edit .env file to set the environment variables
```

Service file:

```bash
cp kali-mcp-server-service.txt /etc/systemd/system/kali-mcp-server.service
# edit the service file to set the environment variables

sudo systemctl daemon-reload
sudo systemctl enable kali-mcp-server.service

# enable the service to start on boot
sudo systemctl enable kali-mcp-server.service
```

For Cloudflare Zero Trust, edit your .env file to set the environment variables for the Cloudflare Zero Trust. Make sure to set the `CF_ZT` to `1` and specify the `CF_CLIENT_ID` and `CF_CLIENT_SECRET`.

```bash
CF_ZT=1
CF_CLIENT_ID=your_client_id
CF_CLIENT_SECRET=your_client_secret
```

---

**Kali MCP Server** is a lightweight API bridge that connects MCP Clients (e.g: Claude Desktop, [5ire](https://github.com/nanbingxyz/5ire)) to the API server which allows excuting commands on a Linux terminal.

This allows the MCP to run terminal commands like `nmap`, `nxc` or any other tool, interact with web applications using tools like `curl`, `wget`, `gobuster`.
 And perform **AI-assisted penetration testing**, solving **CTF web challenge** in real time, helping in **solving machines from HTB or THM**.

## My Medium Article on This Tool

[![How MCP is Revolutionizing Offensive Security](https://miro.medium.com/v2/resize:fit:828/format:webp/1*g4h-mIpPEHpq_H63W7Emsg.png)](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

👉 [**How MCP is Revolutionizing Offensive Security**](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

---

## 🔍 Use Case

The goal is to enable AI-driven offensive security testing by:

- Letting the MCP interact with AI endpoints like OpenAI, Claude, DeepSeek, or any other models.
- Exposing an API to execute commands on a Kali machine.
- Using AI to suggest and run terminal commands to solve CTF challenges or automate recon/exploitation tasks.
- Allowing MCP apps to send custom requests (e.g., `curl`, `nmap`, `ffuf`, etc.) and receive structured outputs.

Here are some example for my testing (I used google's AI `gemini 2.0 flash`)

### Example solving my web CTF challenge in RamadanCTF
https://github.com/user-attachments/assets/dc93b71d-9a4a-4ad5-8079-2c26c04e5397

### Trying to solve machine "code" from HTB
https://github.com/user-attachments/assets/3ec06ff8-0bdf-4ad5-be71-2ec490b7ee27


---

## 🚀 Features

- 🧠 **AI Endpoint Integration**: Connect your kali to any MCP of your liking such as claude desktop or 5ier.
- 🖥️ **Command Execution API**: Exposes a controlled API to execute terminal commands on your Kali Linux machine.
- 🕸️ **Web Challenge Support**: AI can interact with websites and APIs, capture flags via `curl` and any other tool AI the needs.
- 🔐 **Designed for Offensive Security Professionals**: Ideal for red teamers, bug bounty hunters, or CTF players automating common tasks.

---

## 🛠️ Installation

### On your Linux Machine (Will act as MCP Server)
```bash
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server
python3 kali_server.py
```

### On your MCP Client (You can run on Windows or Linux)
- You will want to run `python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000`

#### Configuration for claude desktop:
edit (C:\Users\USERNAME\AppData\Roaming\Claude\claude_desktop_config.json)

```json
{
    "mcpServers": {
        "kali_mcp": {
            "command": "python3",
            "args": [
                "/absolute/path/to/mcp_server.py",
                "--server",
                "http://LINUX_IP:5000/"
            ]
        }
    }
}
```

#### Configuration for [5ire](https://github.com/nanbingxyz/5ire) Desktop Application:
- Simply add an MCP with the command `python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000` and it will automatically generate the needed configuration files.

## 🔮 Other Possibilities

There are more possibilites than described since the AI model can now execute commands on the terminal. Here are some example:

- Memory forensics using Volatility
  - Automating memory analysis tasks such as process enumeration, DLL injection checks, and registry extraction from memory dumps.

- Disk forensics with SleuthKit
  - Automating analysis from disk images, timeline generation, file carving, and hash comparisons.


## ⚠️ Disclaimer:
This project is intended solely for educational and ethical testing purposes. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is strictly prohibited.
The author assumes no responsibility for misuse.
