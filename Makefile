run:
	cd ../solo2/runners/lpc55 && cargo run --release --features board-lpcxpresso55,develop,log-semihosting,piv-authenticator/log-all

build-cortex-m4:
	cargo build --target thumbv7em-none-eabi

