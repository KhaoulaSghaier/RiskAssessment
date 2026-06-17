FROM python:3.13-slim

WORKDIR /artifact

COPY requirement.txt .
RUN pip install -r requirement.txt

RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-mpnet-base-v2')"

COPY . .

WORKDIR /artifact/PST26

CMD ["bash"]