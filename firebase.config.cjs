const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

dotenv.config();

const access = process.env.ACCESS_TOKEN_SECRET;
const refresh = process.env.REFRESH_TOKEN_SECRET;

let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
	const decodedKey = Buffer.from(
		process.env.FIREBASE_SERVICE_ACCOUNT_BASE64,
		"base64",
	).toString("utf8");
	serviceAccount = JSON.parse(decodedKey);
} else {
	serviceAccount = require("./serviceAccountKey.json");
}

initializeApp({
	credential: cert(serviceAccount),
});
const db = getFirestore();

// --- AUTH UTILITIES ---

const generateAccess = (user) => jwt.sign(user, access, { expiresIn: "5m" });

const verify = async (token) => {
	return new Promise((resolve, reject) => {
		jwt.verify(token, access, (err, decoded) => {
			if (err) reject(new Error("bad token"));
			else resolve(decoded);
		});
	});
};

// --- DATABASE UTILITIES ---

const getId = async (collectionName) => {
	const snapshot = await db.collection(collectionName).get();
	const data = snapshot.docs.map((doc) => doc.id);
	return parseInt(data[data.length - 1] || "0") + 1;
};

const signIn = async (email, password) => {
	const snapshot = await db
		.collection("login")
		.where("email", "==", email)
		.get();

	const userDoc = snapshot.docs.find((doc) =>
		bcrypt.compareSync(password, doc.data().hash),
	);

	return !!userDoc;
};

const registerUser = async (data) => {
	const { email, name, phone, address, city, country, password } = data;

	if (!name || !email || !password) {
		throw new Error("please fill in info");
	}

	const hash = bcrypt.hashSync(password, 10);
	const id = String(await getId("login"));
	const refreshToken = jwt.sign({ email }, refresh, { expiresIn: "6h" });

	await db
		.collection("login")
		.doc(id)
		.set({ email, hash, refresh: refreshToken });
	await db.collection("users").doc(id).set({
		email,
		name,
		phone,
		address,
		city,
		country,
	});

	return { id, name, email, phone, address, city, country, refreshToken };
};

const logOutUser = async (email) => {
	await updateData("login", email, { refresh: null });
};

const getUsers = async (email) => {
	const snapshot = await db
		.collection("users")
		.where("email", "==", email)
		.get();

	const data = snapshot.docs.map((doc) => ({
		id: doc.id,
		...doc.data(),
	}));

	return data[0];
};

const editUser = async (data) => {
	const { name, prevEmail, newEmail, phone, address, city, country } = data;

	const userData = {
		name,
		email: newEmail,
		phone,
		address,
		city,
		country,
	};

	await updateData("login", prevEmail, { email: newEmail });
	await updateData("users", prevEmail, userData);

	return userData;
};

const editPassword = async (data) => {
	const { email, prevPassword, newPassword } = data;

	const snapshot = await db
		.collection("login")
		.where("email", "==", email)
		.get();

	const validDoc = snapshot.docs.find((doc) =>
		bcrypt.compareSync(prevPassword, doc.data().hash),
	);

	if (!validDoc) {
		return "Previous password is incorrect";
	}

	const newHash = bcrypt.hashSync(newPassword, 10);
	await updateData("login", email, { hash: newHash });

	return "Password successfully changed";
};

const getAccessToken = async (email) => {
	const user = { email };

	const accessToken = generateAccess(user);
	const refreshToken = jwt.sign(user, refresh, { expiresIn: "6h" });

	await updateData("login", email, { refresh: refreshToken });

	return { access: accessToken, refresh: refreshToken };
};

const refreshLogin = async (token) => {
	const snapshot = await db
		.collection("login")
		.where("refresh", "==", token)
		.get();

	if (snapshot.empty) {
		throw new Error("refresh token is incorrect");
	}

	const loginDoc = snapshot.docs[0];

	try {
		jwt.verify(token, refresh);

		const accessToken = generateAccess({
			email: loginDoc.data().email,
		});

		return accessToken;
	} catch (err) {
		await loginDoc.ref.update({ refresh: null });
		throw new Error("refresh token expired");
	}
};

const updateData = async (collectionName, email, data) => {
	const updateSnapshot = await db
		.collection(collectionName)
		.where("email", "==", email)
		.get();

	for (const document of updateSnapshot.docs) {
		await db.collection(collectionName).doc(document.id).update(data);
	}
};

// --- E-COMMERCE / ORDER MANAGERS ---

const sendOrder = async (data) => {
	const { userId, orderIds, orderQuantities, dateOfPurchase, orderNo } = data;

	const id = String(await getId("orders"));

	await db.collection("orders").doc(id).set({
		user_id: userId,
		order_ids: orderIds,
		order_quantities: orderQuantities,
		date_of_purchase: dateOfPurchase,
		order_no: orderNo,
	});

	return "success";
};

const getPastOrders = async (id) => {
	const ordersSnapshot = await db
		.collection("orders")
		.where("user_id", "==", id)
		.get();

	return ordersSnapshot.docs.map((doc) => doc.data());
};

module.exports = {
	verify,
	signIn,
	registerUser,
	logOutUser,
	getUsers,
	editUser,
	editPassword,
	getAccessToken,
	refreshLogin,
	updateData,
	getId,
	sendOrder,
	getPastOrders,
};
