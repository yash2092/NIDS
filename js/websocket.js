const ws = new WebSocket("ws://localhost:8000/ws/log");

ws.onmessage = function(event) {
    const message = JSON.parse(event.data);
    const logDiv = document.getElementById("log");
    const messageBox = document.createElement("div");
    messageBox.classList.add("message-box");
    messageBox.innerHTML = `[${message.rule}] ${message.packet} | ${message.action}`;

    // Set color based on rule
    if (message.type === 'Log') {
        messageBox.style.color = 'grey';
    } else if (message.type === 'Detection') {
        messageBox.style.color = 'blue';
    } else if (message.type === 'Alert') {
        messageBox.style.color = 'red';
    }

    messageBox.addEventListener("click", function() {
        const dropdown = messageBox.querySelector('.dropdown');
        dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
    });

    const dropdown = document.createElement('div');
    dropdown.classList.add('dropdown');
    const pre = document.createElement('pre');
    pre.textContent = JSON.stringify(message, null, 2);
    dropdown.appendChild(pre);
    messageBox.appendChild(dropdown);
    logDiv.insertBefore(messageBox, logDiv.firstChild); // Add new log to the top
};

ws.onclose = function(event) {
    console.log("WebSocket connection closed");
    setTimeout(() => {
        // Reconnect to the WebSocket after 1 second
        ws = new WebSocket("ws://localhost:8000/ws/log");
    }, 1000);
};

ws.onerror = function(error) {
    console.error("WebSocket error: ", error);
};


