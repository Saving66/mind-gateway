package com.saving.mindgateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.saving.mind.common.constant.RedisConstant;
import com.saving.mind.common.constant.UserInfoConstant;
import com.saving.mind.common.excpetion.BusinessException;
import com.saving.mind.common.utils.JwtUtil;
import com.saving.mind.common.model.TokenInfo;
import com.saving.mind.common.utils.KeyPairUtil;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

/**
 * @author saving
 */
@Component
public class AccessFilter implements GlobalFilter, Ordered {

    @Resource
    private RedisTemplate redisTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        try {
            // 获取请求对象
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            // 判断当前路径是否以/auth开头
            if (path.startsWith("/auth")) {
                // 如果是以/auth开头，直接执行下一个过滤器
                return chain.filter(exchange);
            }

            // 从请求头中获取Token
            String token = request.getHeaders().getFirst("Authorization");
//            if (token != null && token.startsWith("Bearer ")) {
//                token = token.substring(7);
//            } else {
//                return onError(exchange, "Token Not Found", HttpStatus.UNAUTHORIZED);
//            }
            if (token == null) {
                return onError(exchange, "Token Not Found", HttpStatus.UNAUTHORIZED);
            }
            // 对AccessToken进行验证
            PublicKey publicKey = KeyPairUtil.loadPublicKeyFromFile("JwtKey/public_key.pem");
            TokenInfo tokenInfo = JwtUtil.extractObject(token, publicKey, TokenInfo.class, UserInfoConstant.USER_ACCESS_TOKEN);
            Long userId = tokenInfo.getUserId();
            Object o = redisTemplate.opsForValue().get(RedisConstant.USER_ACCESS_TOKEN_KEY + userId);
            if (o == null) {
                return onError(exchange, "Token Expired", HttpStatus.UNAUTHORIZED);
            }
            if (!token.equals(o.toString())) {
                return onError(exchange, "Token Expired", HttpStatus.UNAUTHORIZED);
            }
            // 将当前用户id存入到Header中，转发给微服务
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-USER-ID", userId.toString())
                    .build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        } catch (JsonProcessingException e) {
            // Token解析失败
            return onError(exchange, "Token Parse Error", HttpStatus.UNAUTHORIZED);
        } catch (ExpiredJwtException e) {
            // Token过期
            return onError(exchange, "Token Expired", HttpStatus.UNAUTHORIZED);
        } catch (BusinessException e) {
            // Token类型不匹配
            return onError(exchange, "Token Type Error", HttpStatus.UNAUTHORIZED);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int getOrder() {
        return -100;
    }


    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        // 设置响应头为application/json
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        // 创建一个DataBuffer，并写入错误信息
        DataBuffer buffer = response.bufferFactory().wrap(err.getBytes(StandardCharsets.UTF_8));

        // 写入响应体
        return response.writeWith(Mono.just(buffer));
    }
}
