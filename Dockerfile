FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV VANTA_NETWORK_BACKEND=openflow_hardware
ENV VANTA_NETWORK_TARGET=bare_metal_ovs
ENV VANTA_HARDWARE_INVENTORY_PATH=/app/config/hardware_inventory.json

WORKDIR /app

COPY pyproject.toml README.md requirements.txt /app/
COPY vanta /app/vanta
COPY vanta_core /app/vanta_core
COPY config /app/config
COPY templates /app/templates
COPY ultimate_mtd_controller.py /app/

RUN pip install --no-cache-dir .

EXPOSE 5000 6653

CMD ["vanta-controller"]
