require("dotenv").config();
const express = require("express");
const bodyparser = require("body-parser");
const bcrypt = require("bcrypt-nodejs");
const cors = require("cors");
const knex = require("knex");
const jwt = require("jsonwebtoken");

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

const db = knex({
	client: "pg",
	connection: {
		connectionString: process.env.RENDER_DATABASE_URL,
		ssl: { rejectUnauthorized: false },
		host: process.env.RENDER_HOST,
		port: 5432,
		user: process.env.RENDER_USER,
		password: process.env.RENDER_PASSWORD,
		database: process.env.RENDER_DATABASE,
	},
});

const access = process.env.ACCESS_TOKEN_SECRET;
const refresh = process.env.REFRESH_TOKEN_SECRET;

const app = express();
app.use(bodyparser.json());
app.use(cors());

app.get("/", (req, res) => res.json("success"));

const verifyJWT = (req, res, next) => {
	const authHeader = req.headers["authorization"];
	if (!authHeader) return res.sendStatus(400);
	const token = authHeader?.split(" ")[1];
	jwt.verify(token, access, (err, user) => {
		if (err) return res.status(403).json("bad token");
		req.user = user;
		next();
	});
};

const generateAccess = (user) => jwt.sign(user, access, { expiresIn: "5m" });

app.post("/token", (req, res) => {
	const refreshToken = req.body.token;
	db.select("*")
		.from("login")
		.where({ refresh: refreshToken })
		.then((data) => {
			jwt.verify(data[0].refresh, refresh, (err, user) => {
				if (err) return res.status(403).json("bad token");
				const accessToken = generateAccess({ email: user.email });
				res.json(accessToken);
			});
		})
		.catch((err) => res.status(403).json("refreshToken is incorrect"));
});

app.get("/post", verifyJWT, (req, res) => {
	db.select("*")
		.from("users")
		.then((data) => {
			res.json(data.filter((user) => user.email === req.user.email));
		});
});

app.post("/signin", (req, res) => {
	const { email, password } = req.body;

	if (!email || !password) {
		res.status(400).json("incorrect form submission");
	}
	signIn(email, password).then((data) => {
		if (data) {
			getAccessToken(email).then((data) => {
				const refresh = data.refresh;
				const userData = verify(data.access).then((data) => {
					if (data) {
						return getUsers(email).then((data) => {
							return data;
						});
					}
				});
				res.json({
					refresh,
					...userData,
				});
			});
		} else {
			return "wrong credentials";
		}
	});

	db.select("email", "hash")
		.from("login")
		.where({ email: email })
		.then((data) => {
			const isValid = bcrypt.compareSync(password, data[0].hash);
			if (isValid) {
				return db
					.select("*")
					.from("users")
					.where("email", "=", email)
					.then((data) => {
						const email = data[0].email;
						const user = { email: email };
						const accessToken = generateAccess(user);
						const refreshToken = jwt.sign(user, refresh, { expiresIn: "6h" });
						db.select("*")
							.from("login")
							.where({ email: email })
							.update({ refresh: refreshToken })
							.returning("*")
							.then((data) => {
								res.json({
									accessToken: accessToken,
									refreshToken: data[0].refresh,
								});
							});
					})
					.catch((err) => res.status(400).json("unable to get user"));
			} else {
				res.status(400).json("wrong cridentials");
			}
			// }
		})
		.catch((err) => res.status(400).json("wrong cridentials"));
});
app.post("/logout", (req, res) => {
	const { email } = req.body;
	db("login")
		.where({ email: email })
		.update({ refresh: null })
		.returning("*")
		.then((data) => res.json("log out seccessful"));
});

app.post("/register", (req, res) => {
	const { name, email, password, phone, address, city, country } = req.body;
	res.json({ name, email, password });
	const hash = bcrypt.hashSync(password);

	db.transaction((trx) => {
		trx
			.insert({
				hash: hash,
				email: email,
			})
			.into("login")
			.returning("email")
			.then((loginEmail) => {
				return trx("users")
					.returning("*")
					.insert({
						email: loginEmail[0].email,
						name: capitalizeSentence(name),
						phone: capitalizeSentence(phone),
						address: capitalizeSentence(address),
						city: capitalizeSentence(city),
						country: capitalizeSentence(country),
					})
					.then((user) => {
						res.json(user[0]);
					});
			})
			.then(trx.commit)
			.catch(trx.rollback);
	}).catch((err) => {
		res.status(400).json("unable to register");
		console.log(err);
	});
});

app.post("/edit", (req, res) => {
	const { name, prevEmail, newEmail, phone, address, city, country } = req.body;
	db("login")
		.where({ email: prevEmail })
		.update({ email: newEmail })
		.returning("email")
		.then((loginEmail) => {
			return db("users")
				.where({ email: prevEmail })
				.update({
					email: loginEmail[0].email,
					name: capitalizeSentence(name),
					phone: capitalizeSentence(phone),
					address: capitalizeSentence(address),
					city: capitalizeSentence(city),
					country: capitalizeSentence(country),
				})
				.returning("*")
				.then((data) => res.json(data));
		});
});
app.post("/pass", (req, res) => {
	const { email, prevPassword, newPassword } = req.body;
	const newHash = bcrypt.hashSync(newPassword);

	db.select("email", "hash")
		.from("login")
		.where({ email: email })
		.then((data) => {
			const isValid = bcrypt.compareSync(prevPassword, data[0].hash);
			if (isValid) {
				return db("login")
					.where({ email: email })
					.update({ hash: newHash })
					.then(res.json("Password successfully changed"));
			} else {
				return res.status(400).json("Previous password is incorrect");
			}
		})
		.catch((err) => res.status(400).json("unable to change password"));
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
	const { userId, orderIds, orderQuantities, dateOfPurchase, orderNo } =
		req.body;

	db("orders")
		.insert({
			user_id: userId,
			order_ids: orderIds,
			order_quantities: orderQuantities,
			date_of_purchase: dateOfPurchase,
			order_no: orderNo,
		})
		.then(res.json("success"));
});

app.post("/past-orders", async (req, res) => {
	const { id } = req.body;

	db("orders")
		.where({ user_id: id })
		.returning("*")
		.then((data) => res.json(data));
});

app.listen(4000, () => console.log("app is running"));
