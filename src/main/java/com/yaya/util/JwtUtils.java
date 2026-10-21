package com.yaya.util;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.date.DateField;
import cn.hutool.core.date.DateTime;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.exceptions.ValidateException;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.SecureUtil;
import cn.hutool.crypto.asymmetric.SignAlgorithm;
import cn.hutool.json.JSONException;
import cn.hutool.jwt.JWT;
import cn.hutool.jwt.JWTException;
import cn.hutool.jwt.JWTValidator;
import cn.hutool.jwt.signers.JWTSigner;
import cn.hutool.jwt.signers.JWTSignerUtil;
import lombok.extern.slf4j.Slf4j;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 * JWT工具类
 * 基于hutool工具类生成
 * 基于非对称加密RS256(SHA256withRSA)方式实现
 * 1. 生成token
 * 2. 验证token
 * 3. 获取参数
 *
 * <p>安全说明: 密钥不再硬编码在源码中, 改为从环境变量读取:
 * <pre>
 *   YAYA_JWT_PUBLIC_KEY    Base64 编码的 RS256 公钥
 *   YAYA_JWT_PRIVATE_KEY   Base64 编码的 RS256 私钥
 * </pre>
 * 两个变量都未配置时, 会在启动时生成一对临时密钥并打印警告, 仅适合本地单机开发调试;
 * 重启后旧 Token 会全部失效, 生产/多实例部署请务必配置固定密钥。
 * 可用 {@link CryptoUtils#createRsaKey()} 生成一对密钥后写入环境变量。
 */
@Slf4j
public class JwtUtils {

    /** 环境变量名: Base64 编码的 RS256 公钥 */
    private static final String ENV_PUBLIC_KEY = "YAYA_JWT_PUBLIC_KEY";
    /** 环境变量名: Base64 编码的 RS256 私钥 */
    private static final String ENV_PRIVATE_KEY = "YAYA_JWT_PRIVATE_KEY";
    /** 密钥对 Map 的键名 */
    private static final String KEY_PUBLIC = "publicKey";
    private static final String KEY_PRIVATE = "privateKey";

    /**
     * 解析 JWT 密钥对
     * 1. 优先从环境变量 YAYA_JWT_PUBLIC_KEY / YAYA_JWT_PRIVATE_KEY 读取
     * 2. 任一缺失则生成一对临时密钥, 并打印警告
     *
     * @return 包含 publicKey / privateKey(Base64 字符串)的 Map
     */
    private static Map<String, String> loadKeyPair() {
        String publicKey = StrUtil.trim(System.getenv(ENV_PUBLIC_KEY));
        String privateKey = StrUtil.trim(System.getenv(ENV_PRIVATE_KEY));
        if (StrUtil.isNotBlank(publicKey) && StrUtil.isNotBlank(privateKey)) {
            log.info("JWT 密钥已从环境变量 [{}, {}] 加载", ENV_PUBLIC_KEY, ENV_PRIVATE_KEY);
            return Map.of(KEY_PUBLIC, publicKey, KEY_PRIVATE, privateKey);
        }
        log.warn("未检测到环境变量 [{}, {}], 已生成一组临时 JWT 密钥, 仅适用于本地单机调试; "
                        + "多实例部署或生产环境请配置固定密钥, 否则重启后 Token 将全部失效",
                ENV_PUBLIC_KEY, ENV_PRIVATE_KEY);
        return CryptoUtils.createRsaKey();
    }

    /** 启动时解析得到的密钥对(优先环境变量, 缺失则生成临时密钥) */
    private static final Map<String, String> KEY_PAIR = loadKeyPair();
    //公钥
    private static final String PUBLIC_KEY_STR = KEY_PAIR.get(KEY_PUBLIC);
    //私钥
    private static final String PRIVATE_KEY_STR = KEY_PAIR.get(KEY_PRIVATE);
    //公钥签名器(用来验签)
    private static final JWTSigner PUBLIC_SIGNER;
    //私钥签名器(用来签发)
    private static final JWTSigner PRIVATE_SIGNER;
    // 允许服务器之间存在 5 秒钟的时钟漂移
    private static final long ALLOW_SKEW_SECONDS = 5L;

    //初始化签名器
    static {
        //私钥对象
        PrivateKey privateKey = SecureUtil.generatePrivateKey(SignAlgorithm.SHA256withRSA.getValue(), Base64.decode(PRIVATE_KEY_STR));
        //创建私钥签名器
        PRIVATE_SIGNER = JWTSignerUtil.rs256(privateKey);
        //公钥对象
        PublicKey publicKey = SecureUtil.generatePublicKey(SignAlgorithm.SHA256withRSA.getValue(), Base64.decode(PUBLIC_KEY_STR));
        //创建公钥签名器
        PUBLIC_SIGNER = JWTSignerUtil.rs256(publicKey);
    }

    /**
     * 创建 Token (使用私钥签名)
     *
     * @param claims        自定义业务参数（如 userId, username, roles 等）
     * @param expireMinutes 过期时间（单位：分钟）
     * @return String JWT 字符串
     */
    public static String createToken(Map<String, Object> claims, int expireMinutes) {
        DateTime now = DateTime.now(); //开始时间
        DateTime expTime = now.offsetNew(DateField.MINUTE, expireMinutes); //过期时间
        return JWT.create()
                .addHeaders(Map.of("alg", "RS256", "typ", "JWT")) // 明确声明使用的是 RS256 算法
                .setPayload(JWT.ISSUED_AT, now.getTime() / 1000)      // 签发时间 (秒)
                .setPayload(JWT.EXPIRES_AT, expTime.getTime() / 1000) // 过期时间 (秒)
                .addPayloads(claims)                                  // 业务参数
                .setSigner(PRIVATE_SIGNER)                             // 注入刚刚创建的 RS256 签名器
                .sign();
    }


    /**
     * 校验并获取 JWT 对象 (使用公钥验签 + 严格时间校验)
     *
     * @param token JWT 字符串
     * @return JWT
     * @throws JWTException 校验失败时抛出具体异常原因
     */
    public static JWT validateAndGet(String token) {

        if (StrUtil.isBlank(token)) {
            throw new JWTException("Token 不能为空");
        }

        try {
            JWT jwt = JWT.of(token);

            // 1. 验证签名（拿着公钥去验证是否是由持有私钥的人签发的）
            if (!jwt.verify(PUBLIC_SIGNER)) {
                throw new JWTException("Token 签名验证失败，可能已被篡改");
            }
            // 2. 验证时间（是否过期、是否未到生效时间，允许 5 秒时钟漂移）
            JWTValidator.of(jwt).validateDate(DateTime.now(), ALLOW_SKEW_SECONDS);
            return jwt;
        }catch (Exception e) {
            log.error("Token校验失败:",e);
            if(e instanceof ValidateException){
                String message = e.getMessage();
                if(StrUtil.isNotEmpty(message) && StrUtil.contains(message,"is before now")){
                    throw new JWTException("Token已过期");
                }
            } else if (e instanceof JSONException) {
                String message = e.getMessage();
                if(StrUtil.isNotEmpty(message) && StrUtil.contains(message,"text must begin with '{'")){
                    throw new JWTException("Token结构损坏");
                }
            }
            throw new JWTException("Token 格式非法或解析错误");
        }

    }
    /**
     * 判断 Token 是否有效
     */
    public static boolean isValid(String token) {
        try {
            validateAndGet(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获取 Token 中所有的载荷参数 (内部包含安全校验)
     */
    public static Map<String, Object> getClaims(String token) {
        return validateAndGet(token).getPayloads();
    }

    /**
     * 获取 Token 中指定的某一个参数 (内部包含安全校验)
     */
    public static Object getClaim(String token, String claimKey) {
        return validateAndGet(token).getPayload().getClaim(claimKey);
    }

    /**
     * 获取 Token 还有多久过期（剩余有效时间）
     * @param token JWT 字符串
     * @return long 剩余时间（单位：秒）。如果已过期，返回 <= 0 的值
     */
    public static long getExpiresIn(String token) {
        // validateAndGet 内部会做签名和时间校验，如果已经过期，会直接抛出 JWTException
        // 如果你想在已过期的状态下也能查看它过期了多久，可以改用：JWT jwt = JWT.of(token); jwt.verify(PUBLIC_SIGNER);
        try {
            JWT jwt = validateAndGet(token);
            Long expTimeSec = jwt.getPayload().getClaimsJson().getLong(JWT.EXPIRES_AT);
            if (expTimeSec == null) {
                return 0; // 没有设置过期时间，视为已过期或永不过期（根据业务定义）
            }
            long nowSec = DateTime.now().getTime() / 1000;
            return expTimeSec - nowSec;
        } catch (JWTException e) {
            // 如果是因为过期导致的异常，为了能拿到具体的剩余时间（负数），在这里做二次安全解析
            if (StrUtil.contains(e.getMessage(), "已过期") || StrUtil.contains(e.getLocalizedMessage(), "before now")) {
                JWT jwt = JWT.of(token);
                // 虽过期，但仍需保证签名正确，防止恶意构造
                if (jwt.verify(PUBLIC_SIGNER)) {
                    Long expTimeSec = (Long) jwt.getPayload().getClaimsJson().getLong(JWT.EXPIRES_AT);
                    long nowSec = DateTime.now().getTime() / 1000;
                    return expTimeSec - nowSec; // 返回负数，代表已经过期了多少秒
                }
            }
            throw e; // 其他非法格式异常直接抛出
        }
    }

    /**
     * 获取 Token 的具体过期绝对时间
     * @param token JWT 字符串
     * @return DateTime 过期时间
     */
    public static DateTime getExpirationDate(String token) {
        try {
            JWT jwt = validateAndGet(token);
            Long expTimeSec = jwt.getPayload().getClaimsJson().getLong(JWT.EXPIRES_AT);
            return expTimeSec != null ? DateUtil.date(expTimeSec * 1000) : null;
        } catch (Exception e) {
            // 同理，若过期了仍想获取其历史过期时间：
            if (StrUtil.contains(e.getMessage(), "已过期") || StrUtil.contains(e.getLocalizedMessage(), "before now")) {
                JWT jwt = JWT.of(token);
                if (jwt.verify(PUBLIC_SIGNER)) {
                    Long expTimeSec = jwt.getPayload().getClaimsJson().getLong(JWT.EXPIRES_AT);
                    return DateUtil.date(expTimeSec * 1000);
                }
            }
            throw e;
        }
    }

}
