# Chatty - Full Stack Real-Time Chat Application

Welcome to **Chatty**, a full-stack real-time chat application that allows users to communicate seamlessly. Users can send messages, share pictures, and update their profile pictures effortlessly.

🔗 **Live Demo:** [ChatApp Live](https://fullstack-chat-app-x0jh.onrender.com)

## 🚀 Features

- 🔒 **User Authentication** – Secure login and signup functionality.
- 💬 **Real-Time Messaging** – Chat instantly with friends.
- 🖼️ **Media Sharing** – Send and receive images in chats.
- 👤 **Profile Management** – Update profile pictures and manage account settings.
- 🌐 **Responsive UI** – Optimized for both desktop and mobile.

## 🛠️ Tech Stack

### Frontend:
- **React.js** (with hooks and context API)
- **Tailwind CSS** for styling
- **Socket.io Client** for real-time communication

### Backend:
- **Node.js** with **Express.js**
- **Socket.io Server** for real-time communication
- **MongoDB** with **Mongoose** for database management
- **JWT Authentication** for secure login
- **Cloudinary** for handling image uploads

## 📦 Installation (For Local Development)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Priyanshu3369/fullstack-chat-app.git
   cd fullstack-chat-app
   ```

2. **Setup backend:**
   ```bash
   cd backend
   npm install
   npm start
   ```

3. **Setup frontend:**
   ```bash
   cd frontend
   npm install
   npm start
   ```

4. **Environment Variables:**
   Create a `.env` file in the `server` folder and add:
   ```env
   PORT=5001
   MONGODB_URL=your_mongodb_connection_string
   JWT_SECRET=your_secret_key
   CLOUDINARY_CLOUD_NAME=your_cloudinary_name
   CLOUDINARY_API_KEY=your_cloudinary_api_key
   CLOUDINARY_API_SECRET=your_cloudinary_api_secret
   ```

## 🖥️ Usage

- Access the app live at [ChatApp Live](https://fullstack-chat-app-x0jh.onrender.com).
- Register a new account or log in with existing credentials.
- Start chatting with other users in real-time.
- Upload and share images directly within the chat.
- Update your profile picture from the settings page.

## 🧑‍💻 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## 🙌 Acknowledgments

- Special thanks to all open-source libraries used in this project.

---

Feel free to give a ⭐ if you like this project!

