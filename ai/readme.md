Ollama is perfect for running a local LLM on your laptop efficiently. Here's how to set up using Ollama:

## Install Ollama
For macOS or Linux
```
bash# curl -fsSL https://ollama.com/install.sh | sh
```

After installation, verify it's working:
```
bash# ollama --version
```

## Find a proper model 

Visit https://ollama.com/ and select a model.

For example, store exaone3.5:2.4b on your computer as below.
```
bash# ollama pull exaone3.5:2.4b
```

Then,  run ollama.

For wsl, the following should be run.
```
OLLAMA_HOST=0.0.0.0 OLLAMA_ORIGINS="*" ollama serve
```

## Install or develop a UI

Running in the terminal is cool, but a GUI makes it feel like ChatGPT.

Option A: Web-based UIs (No Coding Required)
If you don't want to build one from scratch, these are the gold standards:

Open WebUI: The most popular choice. It looks exactly like ChatGPT and supports RAG (Document uploading).

Run via Docker: 
```
docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway -v open-webui:/app/data --name open-webui ghcr.io/open-webui/open-webui:main
```

Option B: Build a Simple UI (Python/Streamlit)
If you want to code your own, Streamlit is the fastest way:

```
import streamlit as st
import ollama

st.title("My Local AI")

if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
if prompt := st.chat_input("Ask me anything..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        response = ollama.chat(model='exaone3.5:2.4b', messages=[
            {'role': 'user', 'content': prompt},
        ])
        msg = response['message']['content']
        st.markdown(msg)
        st.session_state.messages.append({"role": "assistant", "content": msg})
```

## Management Commands
Handy commands to keep your workspace clean:

- List installed models: ollama list

- Remove a model: ollama rm exaone3.5:2.4b

- Check logs: journalctl -u ollama (on Linux)
