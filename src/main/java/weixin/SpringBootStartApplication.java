package weixin;

import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.web.WebApplicationInitializer;

/**
 * @author wuyuan
 * 2018-1-7
 * ccb
 *  修改启动类，继承 SpringBootServletInitializer 并重写 configure 方法
 *  tomcat启动要用到，weblogic没试
 */
public class SpringBootStartApplication extends SpringBootServletInitializer implements WebApplicationInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        // 注意这里要指向原先用main方法执行的Application启动类
        return builder.sources(WeixinApplication.class);
    }
}