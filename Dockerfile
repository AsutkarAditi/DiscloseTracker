FROM python:latest


WORKDIR /app


COPY requirements.txt .


RUN pip install --no-cache-dir -r requirements.txt


COPY . .


EXPOSE 8501


ENV STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0


CMD ["streamlit", "run", "scraper.py"]
