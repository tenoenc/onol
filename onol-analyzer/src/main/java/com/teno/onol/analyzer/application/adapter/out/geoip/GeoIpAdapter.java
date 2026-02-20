package com.teno.onol.analyzer.application.adapter.out.geoip;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.teno.onol.analyzer.application.port.out.ResolveGeoIpPort;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.File;
import java.net.InetAddress;

@Slf4j
@Component
public class GeoIpAdapter implements ResolveGeoIpPort {

    private DatabaseReader dbReader;
    // docker-compose 등을 고려하여 외부 경로에서 로드 가능하게 설정
    private static final String DB_PATH = "data/geoip/GeoLite2-City.mmdb";

    @PostConstruct
    public void init() {
        try {
            File database = new File(DB_PATH);
            if (database.exists()) {
                dbReader = new DatabaseReader.Builder(database).build();
                log.info("GeoIP Database loaded successfully.");
            } else {
                log.warn("GeoIP Database not found at: {}. Country resolution will disabled.", DB_PATH);
            }
        } catch (Exception e) {
            log.error("Failed to load GeoIP Database", e);
        }
    }

    @Override
    public String resolveCountryCode(String ip) {
        if (dbReader == null || ip == null) return null;

        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            // 사설 IP(공유기 IP)는 국가가 없음
            if (ipAddress.isSiteLocalAddress() || ipAddress.isLoopbackAddress()) {
                return "INT";
            }
            return dbReader.country(ipAddress).getCountry().getIsoCode();
        } catch (AddressNotFoundException e) {
            return null; // DB에 없는 IP
        } catch (Exception e) {
            return null;
        }
    }
}
