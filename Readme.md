# JWT Authentication Package with Email Verification, RBAC, and Refresh Tokens

This Node.js authentication package provides a robust and secure method for handling user authentication using **JWT (JSON Web Tokens)**. It includes features like **access and refresh tokens**, **role-based access control (RBAC)**, **email verification**, and **password hashing**. This package ensures a seamless and secure user experience with token expiration handling, user role protection, and email confirmation.

## Features

- **JWT-based Authentication**: Generate and verify JWT tokens for secure API communication.
- **Access and Refresh Tokens**: Issue short-lived access tokens and long-lived refresh tokens for better session management.
- **Role-Based Access Control (RBAC)**: Restrict access to routes based on user roles (e.g., Admin, User).
- **Password Hashing**: Securely hash and verify user passwords using **bcryptjs**.
- **Email Verification**: Send a verification email with a unique token for confirming a user’s email address.
- **Error Logging**: Includes basic logging for errors related to authentication operations.
- **Environment Variables**: Use `.env` file to securely store sensitive data like JWT secret keys, email credentials, and token expiration times.

### Steps to Generate an SMTP Password (App Password) for Gmail:

#### Step 1: Enable 2-Step Verification for Your Google Account

1. Go to your [Google Account Security Settings](https://myaccount.google.com/security).
2. Under **"Signing in to Google"**, find and enable **2-Step Verification**.
3. Follow the instructions to complete the process of setting up 2-Step Verification.

#### Step 2: Generate an App Password

1. Once 2-Step Verification is enabled, return to the [App Passwords page](https://myaccount.google.com/apppasswords).
2. You might be asked to sign in again.
3. Under the **"Select app"** dropdown, choose **Mail**.
4. Under the **"Select device"** dropdown, choose **Other (Custom name)** and give it a name like "SMTP" or "App Email."
5. Click **Generate**.
6. Google will generate a 16-character app password. This is the password you will use for your SMTP settings, instead of your regular Gmail password.

#### Step 3: Use the Generated App Password in Your Application

Now, you need to set up your SMTP server settings in your application (in your environment variables or config file). Here's an example of how it can be done.

### Example Configuration Using Environment Variables:

```bash
# .env or configuration file
EMAIL_USER=your-email@gmail.com        # Your Gmail address
EMAIL_PASS=your-generated-app-password  # The 16-character app password you generated
BASE_URL=http://your-app-url.com       # Your application's base URL for links
JWT_SECRET=your-jwt-secret-key        # JWT secret key for signing tokens
JWT_EXPIRATION=1h                     # Access token expiration time (e.g., 1 hour)
JWT_REFRESH_EXPIRATION=7d             # Refresh token expiration time (e.g., 7 days)
SALT_ROUNDS=10                        # Number of salt rounds for bcrypt
```

## Usage

### 1. Initialize the Auth Class

Create an instance of the `Auth` class in your application:

```javascript
const Auth = require('path_to_auth_file');
const auth = new Auth();
```

### 2. Hash Password

Use `hashPassword` to hash a user's password before saving it to the database:

```javascript
const hashedPassword = await auth.hashPassword('userPassword123');
```

### 3. Verify Password

Use `verifyPassword` to compare a user’s entered password with the stored hashed password:

```javascript
const isValid = await auth.verifyPassword('userPassword123', hashedPassword);
```

### 4. Generate Tokens

Generate both **access** and **refresh** tokens after a successful login or registration:

```javascript
const user = { id: 1, email: 'user@example.com', role: 'user', additionalData: {} };
const tokens = auth.generateTokens(user);
console.log(tokens.accessToken, tokens.refreshToken);
```

### 5. Verify Token

Use `verifyToken` to verify the JWT token (e.g., in middleware):

```javascript
const decoded = auth.verifyToken(token); // Decoded payload
```

### 6. Middleware for Role-Based Access Control (RBAC)

Use `verifyRole` middleware to protect routes based on user roles (e.g., admin-only routes):

```javascript
app.get('/admin', auth.verifyRole('admin'), (req, res) => {
    res.json({ message: 'Welcome, Admin!' });
});
```

### 7. Refresh Token

Use `refreshToken` to issue new access tokens using a valid refresh token:

```javascript
const newTokens = auth.refreshToken(refreshToken);
```

### 8. Send Verification Email

Use `sendVerificationEmail` to send an email verification link to the user:

```javascript
const user = { id: 1, email: 'user@example.com' };
await auth.sendVerificationEmail(user);
```

### 9. Verify Email

Verify the email by decoding the token sent to the user's inbox:

```javascript
await auth.verifyEmail(verificationToken);
```

## Example Usage in Express Application

```javascript
const express = require('express');
const Auth = require('path_to_auth_file');
const app = express();
const auth = new Auth();

// Mock user database
const users = [
    { id: 1, email: 'admin@example.com', password: '$2a$10$abc...', role: 'admin' },
    { id: 2, email: 'user@example.com', password: '$2a$10$xyz...', role: 'user' }
];

app.use(express.json());

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ message: 'Invalid email or password.' });
    
    const validPassword = await auth.verifyPassword(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid email or password.' });

    const tokens = auth.generateTokens(user);
    res.json(tokens);
});

// Refresh token route
app.post('/refresh-token', (req, res) => {
    const { refreshToken } = req.body;
    try {
        const newTokens = auth.refreshToken(refreshToken);
        res.json(newTokens);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});

// Protected route (admin only)
app.get('/admin', auth.verifyRole('admin'), (req, res) => {
    res.json({ message: 'Welcome, Admin!' });
});

// Start server
app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

## Error Handling

In case of errors (e.g., invalid tokens, invalid passwords, etc.), meaningful error messages are thrown and can be handled globally in your Express app using a custom error handler.

```javascript
app.use((err, req, res, next) => {
    res.status(500).json({ success: false, message: err.message });
});
```

## License

MIT License

---

### This README provides clear instructions on how to use the package for JWT-based authentication with email verification, role-based access control, and password security.