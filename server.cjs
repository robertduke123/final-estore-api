require("dotenv").config();
const express = require("express");
const bodyparser = require("body-parser");
const cors = require("cors");
const {
	signIn,
	getAccessToken,
	getUsers,
	logOutUser,
	registerUser,
	editUser,
	editPassword,
	sendOrder,
	getPastOrders,
	verify,
	refreshLogin,
} = require("./firebase.config.cjs");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

function capitalizeSentence(sentence) {
	const words = sentence.split(" ");

	const capitalizedWords = words.map((word) => {
		if (word.length === 0) {
			return "";
		}
		return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
	});

	return capitalizedWords.join(" ");
}

const app = express();
app.use(bodyparser.json());
app.use(cors());

app.get("/", (req, res) => res.json("success"));

app.get("/test", (req, res) => {
	getUsers("robduke123@gmail.com").then((data) => res.json(data));
});

app.post("/token", async (req, res) => {
	const refreshToken = req.body.token;
	const token = await refreshLogin(refreshToken);
	await verify(token);

	await getUsers(email).then((data) => res.json(data));
});

app.post("/signin", async (req, res) => {
	try {
		const { email, password } = req.body;

		if (!email || !password) {
			return res.status(400).json("incorrect form submission");
		}

		const valid = await signIn(email, password);

		if (!valid) {
			return res.status(401).json("wrong credentials");
		}

		const tokens = await getAccessToken(email);

		await verify(tokens.access);

		const userData = await getUsers(email);

		return res.json({
			refresh: tokens.refresh,
			userData,
		});
	} catch (err) {
		console.error(err);
		return res.status(500).json("server error");
	}
});

app.post("/logout", (req, res) => {
	const { email } = req.body;
	logOutUser(email).then((data) => res.json(data));
});

app.post("/register", (req, res) => {
	const { name, email, password, phone, address, city, country } = req.body;
	if (!name || !email || !password) {
		res.status(400).json("please fill in info");
	} else {
		const capitalizedData = {
			email,
			password,
			name: capitalizeSentence(name),
			phone: capitalizeSentence(phone),
			address: capitalizeSentence(address),
			city: capitalizeSentence(city),
			country: capitalizeSentence(country),
		};
		registerUser(capitalizedData).then((data) => res.json(data));
	}
});

app.post("/edit", (req, res) => {
	const { name, prevEmail, newEmail, phone, address, city, country } = req.body;
	const capitalizedData = {
		prevEmail,
		newEmail,
		name: capitalizeSentence(name),
		phone: capitalizeSentence(phone),
		address: capitalizeSentence(address),
		city: capitalizeSentence(city),
		country: capitalizeSentence(country),
	};

	editUser(capitalizedData).then((data) => res.json(data));
});
app.post("/pass", (req, res) => {
	editPassword(req.body).then((data) => res.json(data));
});

app.post("/create-payment-intent", async (req, res) => {
	const { amount, name, email, phone, address, city, country } = req.body;

	try {
		const paymentIntent = await stripe.paymentIntents.create({
			amount: amount,
			currency: "nzd",
			payment_method_types: ["card"],
			receipt_email: email,
			shipping: {
				address: {
					city: city,
					country: country,
					line1: address,
				},
				name: name,
				phone: phone,
			},
		});
		res.send({ paymentIntent });
	} catch (err) {
		return res.status(400).send(err.message);
	}
});

app.post("/order", async (req, res) => {
	sendOrder(req.body).then((data) => res.json(data));
});

app.post("/past-orders", async (req, res) => {
	const { id } = req.body;
	getPastOrders(id).then((data) => res.json(data));
});

app.listen(4000, () => console.log("app is running"));
