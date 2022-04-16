package com.pepsiwyl.shiro.cache;

import com.pepsiwyl.utils.ApplicationContextUtils;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Set;


/**
 * @author by pepsi-wyl
 * @date 2022-04-16 14:23
 */

@Slf4j

@Component("redisCacheManger")
// redis 充当Shiro中缓存管理器
public class RedisCacheManger implements CacheManager {

    @Override
    public <K, V> Cache<K, V> getCache(String cacheName) throws CacheException {
        return new RedisCache<K, V>(cacheName);
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    class RedisCache<K, V> implements Cache<K, V> {

        /**
         * cacheName
         */
        private String cacheName;

        /**
         * redisTemplate
         *
         * @return
         */
        private RedisTemplate getRedisTemplate() {
            RedisTemplate redisTemplate = ApplicationContextUtils.getBean("redisTemplate", RedisTemplate.class);
            redisTemplate.setKeySerializer(new StringRedisSerializer());
            redisTemplate.setHashKeySerializer(new StringRedisSerializer());
            return redisTemplate;
        }

        @Override
        public V get(K k) throws CacheException {
            log.info("get key:" + k);
            return (V) getRedisTemplate().opsForHash().get(this.cacheName, k.toString());
        }

        @Override
        public V put(K k, V v) throws CacheException {
            log.info("put key: " + k + " value:" + v);
            getRedisTemplate().opsForHash().put(this.cacheName, k.toString(), v);
            return null;
        }

        @Override
        public V remove(K k) throws CacheException {
            log.info("=============remove=============");
            return (V) getRedisTemplate().opsForHash().delete(this.cacheName, k.toString());
        }

        @Override
        public void clear() throws CacheException {
            log.info("=============clear=============");
            getRedisTemplate().delete(this.cacheName);
        }

        @Override
        public int size() {
            return getRedisTemplate().opsForHash().size(this.cacheName).intValue();
        }

        @Override
        public Set<K> keys() {
            return getRedisTemplate().opsForHash().keys(this.cacheName);
        }

        @Override
        public Collection<V> values() {
            return getRedisTemplate().opsForHash().values(this.cacheName);
        }

    }

}
