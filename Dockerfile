# 后端镜像：基于 Python 3.11 精简版
FROM python:3.11-slim

# 设置工作目录
WORKDIR /app

# 复制依赖文件（利用 Docker 缓存层，依赖不变时跳过安装）
COPY requirements.txt .
COPY web/backend/requirements.txt ./web/backend/

# 安装 Python 依赖
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r web/backend/requirements.txt

# 复制整个项目代码
COPY . .

# 切换到后端目录
WORKDIR /app/web/backend

# 创建数据目录（SQLite 数据库存放位置）
RUN mkdir -p /app/web/backend/data

# 暴露端口
EXPOSE 8000

# 启动命令（生产模式，监听所有网卡）
CMD ["python", "run.py", "--prod", "--host", "0.0.0.0", "--port", "8000"]
