package com.mike.zuul.filters;

import com.mike.zuul.util.JWTUtil;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_TYPE;

/**
 * @Description:
 * @Author: Mike Dong
 * @Date: 2019/12/1 19:06.
 */
@Component
public class TokenFilter extends ZuulFilter {

    private static final Logger log = LoggerFactory.getLogger(TokenFilter.class);

    @Override
    public String filterType() {
        return PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        return 1;
    }

    @Override
    public boolean shouldFilter() {
        RequestContext requestContext = RequestContext.getCurrentContext();
        HttpServletRequest request = requestContext.getRequest();
        //完整路径接口
        String url = request.getRequestURI();
        String local_url = "/login";
        /**
         * 如果是登录接口不进行token验证
         */
        if (url.indexOf(local_url) > -1 || url.indexOf("filedownload") >-1 || url.indexOf("user")>-1) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        String token_header = request.getHeader("token") == null ? "" : request.getHeader("token");
        if (token_header.equals("")) {
            try {
                ctx.setSendZuulResponse(false);
                ctx.getResponse().setContentType("text/html;charset=utf-8");
                ctx.getResponse().getWriter().write("{\"code\": -1,\"message\": \"Token validation must be added\"}");
            } catch (IOException e) {
                log.error(e.getMessage());
            }
            return null;
        }
        if (!JWTUtil.verify(token_header)) {
            try {
                ctx.setSendZuulResponse(false);
                ctx.getResponse().setContentType("text/html;charset=utf-8");
                ctx.getResponse().getWriter().write("{\"code\": -1,\"message\": \"Token authentication failed\"}");
            } catch (IOException e) {
                log.error(e.getMessage());
            }
            return null;
        }
        log.info("Authenticate token successfully!");
        return null;
    }
}
