<p align="left">
  <img src="DataBlinderLogo.png" alt="DataBlinder Logo" width="250"/>
</p>


# 🛡️ DataBlinder

**DataBlinder** is a lightweight Python tool for reversible and encrypted tokenization of sensitive data. It is designed to ensure data privacy and confidentiality when interacting with language models (LLMs), publishing technical logs, or sharing confidencial documents in collaborative environments and others use cases.

🔐 Tokenization is reversible based on dynamic keys generated from a timestamp and the environment variable `DATABLINDER_KEY`. Reversion data is stored **only in encrypted memory**.
<br><br>


## ✨ Highlights

- Secure LLM Prompting: Use with ChatGPT, Claude, Gemini, etc.
- AES-256 Encryption: Sensitive data is never written to disk (except when debug mode -d is explicitly enabled).
- Fast & Practical: 
  - Press `Ctrl+Alt+T` to tokenize
  - Press `Ctrl+Alt+R` to reverse
- Customizable Rules: Define your regex patterns in `rules.cfg`  
- Optional Header: Add a standard security note with `header.cfg`  
- Privacy by Design: Nothing sensitive is logged or stored
<br>


## 🧪 Use Cases

### 1. Prompting LLMs Securely

- **Original**: Analyze access from IP `172.16.254.3` to host `bdserver.prod.local` on port `443`.  
- **Tokenized**: Analyze access from IP `#DB-IP-a41c2ff3` to host `#DB-HOST-9b13a50a` on port `443`.

### 2. Sharing Logs with Third Parties

- **Original**: The `administrator` user executed the command `ping 192.168.1.1` at `13:00`.  
- **Tokenized**: The `#DB-USER-df8a1223` user executed the command `ping #DB-IP-52a3f87b` at `13:00`.

### 3. Judicial Document Review and Redaction

- **Original**: 

Plaintiff: James M. Robertson<br>
SSN: 123-45-6789<br>
Case Number: 22-CV-1047<br>
Address: 455 East 58th Street, Apt 12B, New York, NY 10022<br>
Filing: The plaintiff alleges breach of contract and seeks injunctive relief and compensatory damages.<br>

- **Tokenized**: 

Plaintiff: #DB-NAME-a1b2c3d4<br>
SSN: #DB-SSN-e5f6g7h8<br>
Case Number: #DB-CASE-i9j0k1l2<br>
Address: #DB-ADDR-m3n4o5p6<br>
Filing: The plaintiff alleges breach of contract and seeks injunctive relief and compensatory damages.<br>

<br>


## ⚙️ Installation

```bash
git clone https://github.com/your-user/datablinder.git
cd datablinder
```

```bash
pip install -r requirements.txt
```

🔧 Create a `rules.cfg` with your desired regex rules  
🧾 (Optional) Create a `header.cfg` with your security header  

🔐 Set your secret key:

```bash
set DATABLINDER_KEY=<your_secure_16_digit_strong_password>
```

☑️ For permanent usage, define this key in your system environment variables.

▶️ Run the tool:

```bash
python datablinder.py
```

📌 To autostart with Windows:

1. Press `Win + R`, type `shell:startup`, press `Enter`
2. Create a shortcut pointing to:

```txt
pythonw.exe "C:\Path\To\datablinder\datablinder.py"
```

(Use `pythonw.exe` to avoid showing a terminal window.)
<br><br>



## 🧠 How to Use

🔸 **Tokenize:**

1. Copy text (Ctrl+C)
2. Press `Ctrl+Alt+T`
3. Paste (Ctrl+V)

🔹 **Reverse:**

1. Copy tokenized text (Ctrl+C)
2. Press `Ctrl+Alt+R`
3. Paste (Ctrl+V)
<br>


## 🐞 Debug Mode

To activate debug logging:

```bash
python datablinder.py -d
```

➡️ Logs will be saved to `datablinder.dbg`.
<br><br>


## 📁 Project Structure

```
datablinder/
├── datablinder.py  
├── rules.cfg  
├── header.cfg         (optional)  
├── datablinder.dbg    (debug mode output)  
└── requirements.txt
```
<br>


## ⚠️ LIMITATIONS

While **Data Blinder** provides an effective mechanism for protecting sensitive information through tokenization, it is important to understand its current limitations to align expectations with the tool’s intended use and capabilities.

 🧪 Experimental Nature

This tool was created to demonstrate the foundational concepts behind tokenization. It has not undergone comprehensive security testing. Therefore, **it may contain unknown vulnerabilities**, and its use in production environments is at the discretion and risk of the user.

🛡️ Device-Level Security Dependency

Data Blinder enhances privacy, but it **does not eliminate the risk of compromise by malware** such as clipboard sniffers or keyloggers. These types of threats may still access sensitive content before tokenization or during decryption. Users should **ensure robust endpoint protection**, including updated antimalware tools, operating system patches, and secure configurations.

🕒 Clipboard Exposure Window

The tool relies on clipboard interactions. As such, **any delay between copying sensitive data and triggering the tokenization process can result in temporary exposure**. It is essential to adopt good operational practices, minimizing this time window.

🔍 Regex-Based Detection Limitations

Sensitive data detection is based on user-defined **regular expressions (regex)** stored in the `rules.cfg` file. This approach may **miss patterns that are not explicitly covered** by the current rule set. To increase effectiveness, users are encouraged to **maintain and expand regex rules regularly**, and explore future enhancements with **NLP-based detection** for broader coverage.

🌐 Local Scope Only

Data Blinder operates entirely within the local context of the machine. It **does not integrate directly with external APIs, cloud-native services, or automation pipelines**. To support broader workflows, future versions may include modules or plugins for platforms like **n8n**, allowing integration into security orchestration and automation environments.

👤 User-Dependent Operation

The tool relies on **manual activation via keyboard shortcuts** (e.g., `Ctrl+Alt+T` to tokenize, `Ctrl+Alt+R` to revert). If the correct sequence is not followed—or if users neglect to validate tokenized prompts—**there is a risk that sensitive information may be unintentionally sent to external systems such as LLMs (Large Language Models)**. Users must **verify tokenization before submission** and become familiar with the workflow to ensure safe usage.

🐞 Debug Mode Risk (-d)
When launched with the -d flag (debug mode), DataBlinder will log operational data including clipboard contents and detokenized texts in the plain text file datablinder.dbg.
This can expose sensitive or confidential information to unintended access.
Users should only enable debug mode for troubleshooting and manually delete the log file immediately afterward.
<br><br>



## 📄 License

MIT License – feel free to use, modify, and contribute.
<br><br>


## 💡 Contributions, issues, and suggestions are welcome! :-)
<br><br>

