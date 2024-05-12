# Whales Chat

Whales Chat is a real-time chat application built with Flask and Socket.IO, providing an interactive communication platform. It supports features like user authentication, live chat messages, and an admin dashboard for user management.

## Features

- **User Authentication**: Register, login, and logout functionality.
- **Real-Time Messaging**: Send and receive messages instantly with other users.
- **Admin Dashboard**: Admins can manage users, grant admin rights, and view all users.
- **Persistent Message History**: Messages are saved in a SQLite database and can be reviewed anytime.
- **Chat History Download**: Admins can download the chat history as a CSV file.
- **Dynamic User Status**: View online users in real-time.

## Technologies Used

- **Flask**: A lightweight WSGI web application framework.
- **Flask-SocketIO**: For handling real-time web socket communication.
- **Flask-Login**: For handling user sessions.
- **Flask-WTF**: For form handling and validation.
- **Flask-Bcrypt**: For password hashing.
- **SQLite**: Database to store user and message data.
- **Bootstrap**: For styling and responsive design.

## Getting Started

### Prerequisites

- Python 3.6 or higher
- pip
- virtualenv (optional, but recommended)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/whales-chat.git
cd whales-chat
```
2. **Set up a virtual environment** (optional)
```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```
3. **Install dependencies**
```bash
python install -r requirements.txt
```
4. **Initialize the database**
```bash
flask db upgrade
```
5. **Run the application**
```bash
flask run
```
Or using SocketIO:
```bash
python app.py
```

### Configuration
Make sure to set your environment variables before running the application, especially those related to the database and any third-party services you might be using.

## Usage
After starting the server, open `http://127.0.0.1:5000` in your web browser to access Whales Chat.

## Contributing
Contributions are welcome, and any contributions you make are **greatly appreciated**. Please follow the next steps:

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## License
Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Your Name - wuscdaniel@gmail.com

Project Link: [https://github.com/yourusername/whales-chat](https://github.com/yourusername/whales-chat)

## Acknowledgements

-   Flask
-   [Socket.IO](https://socket.io/)
-   [Bootstrap](https://getbootstrap.com/)
-   [jQuery](https://jquery.com/)
