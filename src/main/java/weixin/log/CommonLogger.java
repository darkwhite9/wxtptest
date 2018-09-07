package weixin.log;

import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

/**
 * @author wuyuan
 * 2018-1-7
 * ccb
 * CommonLogger，屏蔽日志框架差异，目前是log4j，如需使用其他的，就改这个
 * <p>
 * <p>
 * log4j的配置，请董亮按需配置
 */
public class CommonLogger {
    Logger logger;

    @SuppressWarnings("rawtypes")
    public CommonLogger(Class c) {
        logger = Logger.getLogger(c);
    }

    public void info(String message) {
        logger.info(message);
    }

    public void info(String message, Throwable t) {
        logger.info(message, t);
    }

    @SuppressWarnings("rawtypes")
    public void log(Exception ex, HttpServletRequest request) {
        logger.error("************************异常开始*******************************");
//        if(getUser() != null)
//            logger.error("当前用户id是" + getUser().getUserId());
        logger.error(ex);
        logger.error("请求地址：" + request.getRequestURL());
        Enumeration enumeration = request.getParameterNames();
        logger.error("请求参数");
        while (enumeration.hasMoreElements()) {
            String name = enumeration.nextElement().toString();
            logger.error(name + "---" + request.getParameter(name));
        }

        StackTraceElement[] error = ex.getStackTrace();
        for (StackTraceElement stackTraceElement : error) {
            logger.error(stackTraceElement.toString());
        }
        //递归打印Cause
        printCause(ex.getCause());
        logger.error("************************异常结束*******************************");
    }

    /**
     * 递归CauseBy
     *
     * @param cause
     */
    private void printCause(Throwable cause) {
        if (cause != null) {
            logger.error("Cause by:");
            StackTraceElement[] error = cause.getStackTrace();

            if (error.length > 0) {
                logger.error(error[0].toString());
            }

            printCause(cause.getCause());
        }
    }
}
