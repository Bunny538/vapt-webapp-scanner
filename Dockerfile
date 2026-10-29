FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt pyproject.toml README.md ./
RUN pip install --no-cache-dir -r requirements.txt
COPY vapt ./vapt
COPY lab ./lab
RUN pip install --no-cache-dir -e . && useradd -m scanner
USER scanner
# Scanner image: `docker run --rm vapt scan http://host:port`. The lab target reuses this image.
ENTRYPOINT ["vapt"]
