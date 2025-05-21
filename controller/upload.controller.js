import User from "../model/User.js"

export const uploadAvatar = async (req, res) => {

    const url = `/upload/users/${req.file.originalname}`

    await User.updateOne({
        _id: req.userId
    }, {
        avatar: url
    })
    res.json({
        url: url
    })
}

export const uploadVideo = async (req, res) => {
    try {
        const fileUrl = `/upload/lessons/${req.file.originalname}`;

        res.status(200).json({
            message: "Сабақтың бейнесі сәтті жүктелді",
            url: fileUrl,
        });
    } catch (error) {
        res.status(500).json({
            message: "Бейнені жүктеу кезіндегі қате",
            error: error.message,
        });
    }
}