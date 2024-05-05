// express 모듈을 불러와서 애플리케이션 인스턴스 생성
const express = require('express');
const app = express();

// CORS 설정을 위한 모듈 불러오기
const cors = require('cors');
app.use(cors());

// JWT(Json Web Token) 모듈 불러오기
const jwt = require('jsonwebtoken');

// posts 모듈 불러오기
const posts = require('./posts');

// 쿠키 파싱을 위한 모듈 불러오기
const cookieParser = require('cookie-parser');
app.use(cookieParser());

// 시크릿 키 설정
const secretKey = 'nodejs';
const topSecretKey = 'nodenodejs';

// 리프레시 토큰 저장을 위한 배열
const refreshTokens = [];

// JSON 데이터 파싱을 위한 미들웨어 설정
app.use(express.json());

// 로그인 엔드포인트
app.post('/login', (req, res) => {
    // 사용자명 추출
    const username = req.body.username;
    // 사용자 객체 생성
    const user = { name: username };
    // 액세스 토큰 생성
    const accessToken = jwt.sign(user, secretKey, { expiresIn: '30s' });
    // 리프레시 토큰 생성 및 저장
    const refreshToken = jwt.sign(user, topSecretKey, { expiresIn: '2m' });
    refreshTokens.push(refreshToken);
    // 쿠키에 리프레시 토큰 저장
    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
    });
    // 액세스 토큰 응답
    res.json({ accessToken: accessToken });
});

// 포스트 목록을 반환하는 엔드포인트
app.get('/posts', authMiddleware, (req, res) => {
    res.json(posts);
});

// 사용자 권한 검사를 위한 미들웨어 함수
function authMiddleware(req, res, next) {
    // 헤더에서 토큰 추출
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    // 토큰이 없으면 401 에러 응답
    if (!token) return res.sendStatus(401);
    // 토큰 검증
    jwt.verify(token, secretKey, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// 액세스 토큰 재발급을 위한 엔드포인트
app.get('/refresh', (req, res) => {
    // 쿠키에서 리프레시 토큰 추출
    const cookies = req.cookies;
    if (!cookies) return res.sendStatus(401);
    const refreshToken = cookies.jwt;
    // 리프레시 토큰 유효성 검사
    if (!refreshTokens.includes(refreshToken)) {
        return res.sendStatus(403);
    }
    jwt.verify(refreshToken, topSecretKey, (err, user) => {
        if (err) return res.sendStatus(403);
    });
    // 액세스 토큰 재발급
    const accessToken = jwt.sign({ name: username }, secretKey, {
        expiresIn: '30s',
    });
    // 액세스 토큰 응답
    res.json({ accessToken: accessToken });
});

// 서버 4000번 포트 설정 및 서버 시작
const port = 4000;
app.listen(port, () => {
    console.log(`listening on port ${port}`);
});
