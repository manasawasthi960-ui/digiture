# 🛡️ Digiture

### A Windows-First Digital Security & Hygiene Application

Digiture is a desktop application in development focused on helping users understand their device's security and digital hygiene through clear explanations, transparent checks, and user-controlled actions.

The goal is to make digital security easier to understand by showing users what a check examines, what its findings mean, and how they can verify whether a recommended fix worked.

> **Development status:** Early development. The current interface is a prototype. Real security checks, remediation, and verification features are not yet fully implemented.

---

## 🎯 Vision

Digiture aims to make everyday digital security more understandable and accessible.

### Core Principles

* **Transparency:** Explain what each check examines and why it matters.
* **User control:** Let users review and approve proposed changes before applying them.
* **Evidence-based findings:** Distinguish actual check results from examples or simulated data.
* **Safe remediation:** Prefer reversible, clearly explained actions.
* **Verification:** Recheck the relevant setting after a fix instead of assuming it worked.
* **Privacy:** Minimize unnecessary collection and storage of personal information.

## ✨ Planned Features

The following features are part of the project vision and roadmap, not claims about current functionality.

* 🛡️ Device security and digital hygiene checks
* 🔍 Clear findings with supporting evidence
* 📋 Understandable explanations of potential risks
* 🛠️ User-approved remediation recommendations
* ✅ Verification of changes after remediation
* 📊 A dashboard for reviewing check results
* 🔐 Privacy-conscious local data handling

## 🧰 Technology Stack

| Technology | Purpose                                       |
| ---------- | --------------------------------------------- |
| React      | User interface                                |
| TypeScript | Frontend development                          |
| Vite       | Development server and frontend build tooling |
| Tauri 2    | Desktop application framework                 |
| Rust       | Native application logic                      |
| npm        | JavaScript dependency management              |

## 🖥️ Current Development Status

* [x] Initial Tauri + React + TypeScript project setup
* [x] Initial dashboard interface prototype
* [x] Basic Git and GitHub version-control workflow
* [ ] Implement real device security checks
* [ ] Define a structured findings and evidence model
* [ ] Add user-approved remediation workflows
* [ ] Implement post-remediation verification
* [ ] Add appropriate tests and security reviews
* [ ] Prepare a stable Windows release

The checklist will be updated as functionality is implemented and tested.

## 🚀 Getting Started

### Prerequisites

Install the following tools before running the project:

* [Node.js](https://nodejs.org/)
* [Rust](https://www.rust-lang.org/tools/install)
* [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
* [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/)

For Windows development, configure the prerequisites described in the [Tauri prerequisites guide](https://v2.tauri.app/start/prerequisites/).

### Installation

Clone the repository:

```bash
git clone https://github.com/manasawasthi960-ui/digiture.git
cd digiture
```

Install dependencies:

```bash
npm install
```

Start the desktop application in development mode:

```bash
npm run tauri dev
```

If Rust is installed but not recognized in a new terminal, check that the Rust Cargo binary directory is available in your system's `PATH`.

## 🗺️ Roadmap

### Phase 1 — Foundation

Establish the desktop interface, project structure, and development workflow.

### Phase 2 — Reliable Checks

Implement carefully scoped checks that inspect real system state and report what they actually observe.

### Phase 3 — Findings and Evidence

Present results with explanations, severity, supporting evidence, and clear limitations.

### Phase 4 — Safe Remediation

Introduce optional fixes with explicit user approval and appropriate safeguards.

### Phase 5 — Verification

Recheck relevant system state and report whether each action succeeded, failed, or could not be verified.

### Phase 6 — Release Readiness

Add automated tests, security reviews, documentation, and Windows packaging.

## 🔒 Security Philosophy

Digiture should not claim that a device is secure merely because a dashboard looks healthy.

A check should report what it actually examined. Recommendations should explain their potential effects. Changes should require appropriate user authorization, and results should be verified wherever possible.

Digiture is under active development and should not yet be treated as a replacement for established security software.

## 🤝 Contributing

The project is currently under active development. Suggestions, issue reports, and constructive feedback are welcome.

Before contributing, please check the project's current functionality and roadmap so that planned features are not mistaken for implemented ones.

## 📄 Lic
