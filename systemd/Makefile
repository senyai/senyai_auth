.PHONY: install start

install:
	@echo "Installing systemd services..."
	@cp *.service *.target /etc/systemd/system/
	@systemctl daemon-reload
	@systemctl enable senyai-auth.target
	@echo "Done. Run 'make start' to start services"
start:
	@systemctl start senyai-auth.target
stop:
	@systemctl stop senyai-auth.target
