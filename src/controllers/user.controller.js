import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { User } from "../models/user.model.js";
import jwt from "jsonwebtoken";

const registerUser = asyncHandler(async (req, res) => {
	const { username, email, fullname, password } = req.body;

	if (
		[fullname, email, username, password].some(field => field?.trim() === "")
	) {
		throw new ApiError(400, "All fields are required");
	}

	const existedUser = await User.findOne({
		$or: [{ username }, { email }],
	});

	if (existedUser) {
		throw new ApiError(409, "User with email or username already exists");
	}

	const avatarLocalPath = req.files?.avatar[0]?.path;

	let coverImageLocalPath;
	if (
		req.files &&
		Array.isArray(req.files.coverImage) &&
		req.files.coverImage.length > 0
	) {
		coverImageLocalPath = req.files.coverImage[0].path;
	}

	if (!avatarLocalPath) {
		throw new ApiError(400, "Avatar file is required");
	}

	const avatar = await uploadOnCloudinary(avatarLocalPath);
	const coverImage = await uploadOnCloudinary(coverImageLocalPath);

	if (!avatar) {
		throw new ApiError(400, "Avatar file is required");
	}

	const user = await User.create({
		fullname,
		avatar: avatar.url,
		coverImage: coverImage?.url || "",
		email,
		password,
		username: username.toLowerCase(),
	});

	const createdUser = await User.findById(user._id).select(
		"-password -refreshToken"
	);

	if (!createdUser) {
		throw new ApiError(500, "Something went wrong while registering the user");
	}

	return res
		.status(201)
		.json(new ApiResponse(200, createdUser, "User registered Successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
	const { email, username, password } = req.body;

	if (!username && !email)
		throw new ApiError(400, "username or email is required");

	const user = await User.findOne({
		$or: [{ username }, { email }],
	});

	if (!user) throw new ApiError(404, "user does not exist");

	const isPasswordValid = await user.isPasswordCorrect(password);

	if (!isPasswordValid) throw new ApiError(401, "invalid user credentials");

	const { refreshToken, accessToken } = await generateAccessAndRefreshToken(
		user._id
	);

	const loggedInUser = await User.findById(user._id).select(
		"-password -refreshToken"
	);

	const options = {
		httpOnly: true,
		secure: true,
	};

	return res
		.status(200)
		.cookie("accessToken", accessToken, options)
		.cookie("refreshToken", refreshToken, options)
		.json(
			new ApiResponse(
				200,
				{
					user: loggedInUser,
					accessToken,
					refreshToken,
				},
				"user loggedin successfully"
			)
		);
});

const logoutUser = asyncHandler(async (req, res) => {
	await User.findByIdAndUpdate(
		req.user._id,
		{
			$set: {
				refreshToken: undefined,
			},
		},
		{
			new: true,
		}
	);

	const options = {
		httpOnly: true,
		secure: true,
	};

	return res
		.status(200)
		.clearCookie("accessToken", options)
		.clearCookie("refreshToken", options)
		.json(new ApiResponse(200, {}, "User logged Out"));
});

const generateAccessAndRefreshToken = async userId => {
	try {
		const user = await User.findById(userId);
		const accessToken = user.generateAccessToken();
		const refreshToken = user.generateRefreshToken();

		user.refreshToken = refreshToken;
		await user.save({ validateBeforeSave: false });

		return { refreshToken, accessToken };
	} catch (error) {
		throw new ApiError(
			500,
			"something went wrong while generating refresh and access token"
		);
	}
};

const refreshAccessToken = asyncHandler(async (req, res) => {
	const incomingRefreshToken =
		req.cookies.refreshToken || req.body.refreshToken;

	if (!incomingRefreshToken) throw new ApiError(401, "unauthorized request");

	try {
		const decodedToken = jwt.verify(
			incomingRefreshToken,
			process.env.REFRESH_TOKEN_SECRET
		);

		const user = await User.findById(decodedToken?._id);

		if (!user) throw new ApiError(401, "invalid refresh token");
		if (user?.refreshToken !== incomingRefreshToken)
			throw new ApiError(401, "refresh token expired or taken");

		const options = {
			httpOnly: true,
			secure: true,
		};
		const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
			user._id
		);

		return res
			.status(200)
			.cookie("accessToken", accessToken, options)
			.cookie("refreshToken", refreshToken, options)
			.json(
				new ApiResponse(
					200,
					{
						accessToken,
						refreshToken,
					},
					"access token refreshed successfully"
				)
			);
	} catch (error) {
		throw new ApiError(401, error?.message || "invalid refresh token");
	}
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
	const { oldPassword, newPassword } = req.body;

	const user = await User.findById(req.user?._id);

	const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
	if (!isPasswordCorrect) throw new ApiError(400, "invalid old password");

	user.password = newPassword;
	await user.save({ validateBeforeSave: false });

	return res
		.status(200)
		.json(new ApiResponse(200, {}, "password changed successfully"));
});

const getCurrentUser = asyncHandler((req, res) => {
	return res
		.status(200)
		.json(new ApiResponse(200, req.user, "current user fetched successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
	const { fullname, email } = req.body;

	if (!fullname || !email) {
		throw new ApiError(400, "all fields are required");
	}

	const user = await User.findByIdAndUpdate(
		req.user?._id,
		{
			$set: {
				fullname,
				email,
			},
		},
		{ new: true }
	).select("-password");

	return res
		.status(200)
		.json(new ApiResponse(200, user, "account details updated successfully"));
});

const updateAvatar = asyncHandler(async (req, res) => {
	const avatarLocalPath = req.file?.path;

	if (!avatarLocalPath) throw new ApiError(400, "avatar file is missing");

	const avatar = await uploadOnCloudinary(avatarLocalPath);
	if (!avatar) throw new ApiError(400, "error while uploding avatar");

	const user = await User.findByIdAndUpdate(
		req.user?._id,
		{ $set: { avatar: avatar.url } },
		{ new: false }
	).select("-password");

	return res
		.status(200)
		.json(new ApiResponse(200, user, "avatar updated successfully"));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
	const coverImageLocalPath = req.file?.path;

	if (!coverImageLocalPath)
		throw new ApiError(400, "cover image file is missing");

	const coverImage = await uploadOnCloudinary(coverImageLocalPath);
	if (!coverImage) throw new ApiError(400, "error while uploding cover image");

	const user = await User.findByIdAndUpdate(
		req.user?._id,
		{ $set: { coverImage: coverImage.url } },
		{ new: false }
	).select("-password");

	return res
		.status(200)
		.json(new ApiResponse(200, user, "cover image updated successfully"));
});

const getUserCoverImage = asyncHandler(async (req, res) => {
	const { username } = req.params;

	if (!username?.trim()) throw new ApiError(400, "username is missing");

	const channel = await User.aggregate([
		{
			$match: {
				username: username?.toLowerCase(),
			},
		},
		{
			$lookup: {
				from: "subscriptions",
				localField: "_id",
				foreignField: "channel",
				as: "subscribers",
			},
		},
		{
			$lookup: {
				from: "subscriptions",
				localField: "_id",
				foreignField: "subscriber",
				as: "subscribedTo",
			},
		},
		{
			$addFields: {
				subscriberCount: {
					$size: "$subscribers",
				},
				channelSubscribedToCount: {
					$size: "$subscribedTo",
				},
				isSubscribed: {
					$condition: {
						if: { $in: [req.user?._id, "$subscribers.subscriber"] },
						then: true,
						else: false,
					},
				},
			},
		},
		{
			$project: {
				fullname: 1,
				username: 1,
				subscriberCount: 1,
				channelSubscribedToCount: 1,
				isSubscribed: 1,
				avatar: 1,
				coverImage: 1,
				email: 1,
			},
		},
	]);

	if (!channel?.length) throw new ApiError(404, "channel does not exist");

	return res
		.status(200)
		.json(
			new ApiResponse(200, channel[0], "user channel fetched successfully")
		);
});

export {
	registerUser,
	loginUser,
	logoutUser,
	refreshAccessToken,
	changeCurrentPassword,
	getCurrentUser,
	updateAccountDetails,
	updateAvatar,
	updateUserCoverImage,
	getUserCoverImage,
};
