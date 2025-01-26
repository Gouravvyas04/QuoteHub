const express = require('express');
const app = express();
const path = require('path');
const userModel = require('./models/user');
const postModel = require('./models/posts');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key'; // Use env variables for production

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.render('index');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/logout', (req, res) => {
    res.cookie('token', '', { httpOnly: true, maxAge: 0 });
    res.redirect('/login');
});

app.get('/like/:id', isLoggedIn, async (req, res) => {
    try {
        const post = await postModel.findOne({ _id: req.params.id }).populate("user");

        // If the user has already liked the post, unlike it
        if (post.likes.indexOf(req.user._id) === -1) {
            post.likes.push(req.user._id);  // Add user to likes array
        } else {
            post.likes.splice(post.likes.indexOf(req.user._id), 1);  // Remove user from likes array
        }
        
        await post.save();
        res.redirect('/profile');
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

app.get('/profile', isLoggedIn, async (req, res) => {
    try {
        const user = await userModel.findOne({ email: req.user.email }).populate("posts");
        res.render('profile', { user });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});


app.post('/post', isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({email: req.user.email});
    let content = req.body.content;
    let post = await postModel.create({
        user: user._id,
        content
    });
    user.posts.push(post._id);
    await user.save();
    res.redirect("/profile");
});

app.get('/create', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;
        let user = await userModel.findOne({ email });
        if (user) {
            return res.status(400).send('Email already in use');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await userModel.create({
            username,
            name,
            email,
            password: hashedPassword,
        });

        res.redirect('/profile'); // Redirect to login page
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.post('/create', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;

        // Check if email is already in use
        let user = await userModel.findOne({ email });
        if (user) {
            return res.status(400).send('Email already in use');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = await userModel.create({
            username,
            name,
            email,
            password: hashedPassword,
        });

        // Generate a JWT token for the new user
        const token = jwt.sign(
            { email: newUser.email, userid: newUser._id },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Set the JWT token as a cookie
        res.cookie('token', token, { httpOnly: true });

        // Redirect to profile
        res.redirect('/profile');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.post('/register', async (req, res) => {
    try {
        const { username, name, email, password } = req.body;

        // Check if email is already in use
        let user = await userModel.findOne({ email });
        if (user) {
            return res.status(400).send('Email already in use');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = await userModel.create({
            username,
            name,
            email,
            password: hashedPassword,
        });

        // Generate a JWT token for the new user
        const token = jwt.sign(
            { email: newUser.email, userid: newUser._id },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Set the JWT token as a cookie
        res.cookie('token', token, { httpOnly: true });

        // Redirect to profile
        res.redirect('/profile');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        let user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).send('Invalid email or password');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid email or password');
        }

        const token = jwt.sign(
            { email: user.email, userid: user._id },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.cookie('token', token, { httpOnly: true });
        res.redirect("/profile");
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

function isLoggedIn(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect("/login");
    }

    try {
        const data = jwt.verify(token, JWT_SECRET);
        req.user = data;
        next(); 
    } catch (err) {
        return res.redirect("/login"); 
    }
}

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
