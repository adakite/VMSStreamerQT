SHELL := /bin/bash

QT_PREFIX ?= /opt/homebrew/opt/qt
BUILD_DIR ?= build
APP_NAME ?= VMSstreamerQt
CMAKE ?= cmake

.PHONY: all configure build clean run open help

all: build

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$(QT_PREFIX)

build: configure
	$(CMAKE) --build $(BUILD_DIR)

run: build
	@if [[ "$(shell uname)" == "Darwin" ]]; then \
		$(BUILD_DIR)/$(APP_NAME).app/Contents/MacOS/$(APP_NAME); \
	else \
		$(BUILD_DIR)/$(APP_NAME); \
	fi

open: build
	@if [[ "$(shell uname)" == "Darwin" ]]; then \
		open $(BUILD_DIR)/$(APP_NAME).app; \
	else \
		$(BUILD_DIR)/$(APP_NAME); \
	fi

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "make build     # configure + build"
	@echo "make run       # run the app"
	@echo "make open      # open the .app on macOS"
	@echo "make clean     # remove build directory"
	@echo "make QT_PREFIX=/path/to/Qt build"
