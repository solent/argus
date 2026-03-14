FROM ubuntu:24.04

# Installer Python 3 et dépendances système + LLVM 19
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    clang-19 libclang-19-dev \
    build-essential git unzip curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Créer un venv Python
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"


# Installer les packages Python
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir clang==19.1.7

# Copier le code source
COPY src/ ./src

# Cloner Exploit-DB dans src/
RUN git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git ./src/classes/exploitdb

VOLUME ["/data"]

EXPOSE 8000

# Lancer le serveur
CMD ["uvicorn", "src.server:app", "--host", "0.0.0.0", "--port", "8000"]


# COMMANDES POUR BUILD ET DEPLOY
# docker build -t backend .
# docker tag backend votre_image
# docker push votre_image

# gcloud run deploy backend --image votre_image --region europe-west1 --platform managed --allow-unauthenticated --port 8000 --set-env-vars OPENROUTER_API_KEY="hidden"   --timeout=300


# COMMANDES POUR BUILD ET DEPLOY LOCAL
# docker build -t backend .   
# docker run -p 8000:8000 -e OPENROUTER_API_KEY="hidden" -e MODEL_NAME="deepseek/deepseek-chat" backend
