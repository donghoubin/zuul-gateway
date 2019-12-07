package com.mike.zuul.feign;

import com.mike.zuul.model.VerifyResponseInfo;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * @Description:
 * @Author: Mike Dong
 * @Date: 2019/12/1 19:17.
 */
@FeignClient(value = "authentication-service")
public interface AuthenticationService {

    @GetMapping(value = "/verify")
    public ResponseEntity<VerifyResponseInfo> verify(@RequestParam("token") String token );
}
