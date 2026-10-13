# Makefile for RedPearl v1.1.0
INSTALL_DIR = /usr/local/bin
PYTHON = python3
SCRIPT_NAME = RedPearl_2.py
TARGET = redpearl
CURRENT_DIR = $(shell pwd)

.PHONY: all install uninstall clean

all:
    @echo "=========================================================="
    @echo " RedPearl v1.1.0 Enterprise Makefile"
    @echo "=========================================================="
    @echo " Usage:"
    @echo "   sudo make install    - Install dependencies and setup 'redpearl' globally"
    @echo "   sudo make uninstall  - Remove global 'redpearl' command"
    @echo "   make clean           - Clean logs, caches, and local databases"
    @echo "=========================================================="

install:
    @echo "[*] Installing required core dependencies..."
    $(PYTHON) -m pip install --upgrade defusedxml
    @echo "[*] Generating global shell execution wrapper..."
    @echo "#!/bin/bash" > $(TARGET)
    @echo "cd $(CURRENT_DIR) && $(PYTHON) $(SCRIPT_NAME) \"\$$@\"" >> $(TARGET)
    chmod +x $(TARGET)
    @echo "[*] Moving $(TARGET) to $(INSTALL_DIR) (requires sudo privileges)..."
    sudo mv $(TARGET) $(INSTALL_DIR)/$(TARGET)
    @echo "[+] Installation successful! You can now type 'redpearl' from anywhere."

uninstall:
    @echo "[*] Removing global command from $(INSTALL_DIR)..."
    sudo rm -f $(INSTALL_DIR)/$(TARGET)
    @echo "[+] Uninstallation complete."

clean:
    @echo "[*] Purging local caches, session logs, and SQLite state files..."
    rm -rf __pycache__ *.pyc
    rm -f redpearl_enterprise_state.db redpearl_session.log oui.txt mac_vendors.json
    @echo "[+] Workspace cleaned successfully."
