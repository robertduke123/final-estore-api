"use server";
import { initializeApp } from "firebase/app";
import {
	getFirestore,
	collection,
	query,
	where,
	getDocs,
	doc,
	updateDoc,
	setDoc,
} from "firebase/firestore";
import dotenv from "dotenv";

import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();
const access = `${process.env.ACCESS_TOKEN_SECRET}`;
const refresh = `${process.env.REFRESH_TOKEN_SECRET}`;

const firebaseConfig = {
	apiKey: `${process.env.FIREBASE_API_KEY}`,
	authDomain: `${process.env.FIREBASE_AUTH_DOMAIN}`,
	projectId: `${process.env.FIREBASE_PROJECT_ID}`,
	storageBucket: `${process.env.FIREBASE_STORAGE_BUCKET}`,
	messagingSenderId: `${process.env.FIREBASE_MESSAGING_SENDER_ID}`,
	appId: `${process.env.FIREBASE_APP_ID}`,
};
// const firebaseConfig = require("./firebase.config.js");

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

const generateAccess = (user) => jwt.sign(user, access, { expiresIn: "5m" });

const verify = async (token) => {
	return new Promise((resolve, reject) => {
		jwt.verify(token, access, (err, decoded) => {
			if (err) {
				reject(new Error("bad token"));
			} else {
				resolve(decoded);
			}
		});
	});
};

const getId = async () => {
	const snapshot = await getDocs(collection(db, "users"));
	const data = await snapshot.docs.map((doc) => {
		return doc.id;
	});
	return parseInt(data[data.length - 1]) + 1;
};

const signIn = async (email, password) => {
	const snapshot = await getDocs(
		query(collection(db, "login"), where("email", "==", email)),
	);

	const userDoc = snapshot.docs.find((doc) => {
		return bcrypt.compareSync(password, doc.data().hash);
	});

	return !!userDoc;
};

const registerUser = async (data) => {
	const { email, name, phone, address, city, country, password } = data;
	const hash = bcrypt.hashSync(password, 10);
	const id = String(await getId("login"));
	const refreshToken = jwt.sign({ email }, refresh, { expiresIn: "6h" });

	if (!name || !email || !password) {
		throw new Error("please fill in info");
	} else {
		await setDoc(doc(db, "login", id), { email, hash, refresh: refreshToken });
		await setDoc(doc(db, "users", id), {
			email,
			name,
			phone,
			address,
			city,
			country,
		});
		return { id, name, email, phone, address, city, country, refreshToken };
	}
};

const logOutUser = async (email) => {
	updateData("login", email, { refresh: null });
	return;
};

const getUsers = async (email) => {
	try {
		const userQ = query(collection(db, "users"), where("email", "==", email));
		const snapshot = await getDocs(userQ);
		const data = await snapshot.docs.map((doc) => ({
			id: doc.id,
			...doc.data(),
		}));

		return data[0];
	} catch (err) {
		console.error(err);
		throw err;
	}
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
	const newHash = bcrypt.hashSync(newPassword);
	const snapshot = await getDocs(
		query(collection(db, "login"), where("email", "==", email)),
	);

	const isValid = snapshot.docs.find((doc) => {
		return bcrypt.compareSync(prevPassword, doc.data().hash);
	});
	if (isValid) {
		updateData("login", email, { hash: newHash });
		return "Password successfully changed";
	} else {
		return "Previous password is incorrect";
	}
};

const getAccessToken = async (email) => {
	const user = { email: email };
	const accessToken = generateAccess(user);
	const refreshToken = jwt.sign(user, refresh, { expiresIn: "6h" });

	updateData("login", email, { refresh: refreshToken });
	return { access: accessToken, refresh: refreshToken };
};

const refreshLogin = async (token) => {
	const snapshot = await getDocs(
		query(collection(db, "login"), where("refresh", "==", token)),
	);

	if (snapshot.empty) {
		throw new Error("refresh token is incorrect");
	}

	const doc = snapshot.docs[0];

	jwt.verify(token, refresh);

	const accessToken = generateAccess({ email: doc.data().email });
	return accessToken;
};

const updateData = async (collectionName, email, data) => {
	const updateQuery = query(
		collection(db, collectionName),
		where("email", "==", email),
	);
	const updateQuerySnapshot = await getDocs(updateQuery);
	await updateQuerySnapshot.docs.map((document) => {
		const docRef = doc(db, collectionName, document.id);
		updateDoc(docRef, data);
	});
};

const sendOrder = async (data) => {
	const { userId, orderIds, orderQuantities, dateOfPurchase, orderNo } = data;
	const id = String(await getId("orders"));
	await setDoc(doc(db, "orders", id), {
		user_id: userId,
		order_ids: orderIds,
		order_quantities: orderQuantities,
		date_of_purchase: dateOfPurchase,
		order_no: orderNo,
	});
	return "success";
};

const getPastOrders = async (id) => {
	const ordersQuery = query(
		collection(db, "orders"),
		where("user_id", "==", id),
	);
	const ordersSnapshot = await getDocs(ordersQuery);
	await ordersSnapshot.docs.map((doc) => {
		return doc.data();
	});
};

export {
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
