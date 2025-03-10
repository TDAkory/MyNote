#!/bin/bash

# 检查参数数量
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <command>"
    echo "Available commands: sync"
    exit 1
fi

# 获取命令参数
COMMAND=$1

# 根据命令执行相应的操作
case $COMMAND in
    sync)
        echo "Executing git pull origin main..."
        git pull origin main
        if [ $? -ne 0 ]; then
            echo "Error: git pull origin main failed"
            exit 1
        fi

        echo "Executing git submodule update..."
        git submodule update --remote
        if [ $? -ne 0 ]; then
            echo "Error: git submodule update failed"
            exit 1
        fi
        ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Available commands: sync"
        exit 1
        ;;
esac

echo "Commands executed successfully."