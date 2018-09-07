package weixin.log;

/**
 * @author wuyuan
 * 2018-1-7
 * ccb
 * 日志工厂,创建了自定义的CommonLogger
 * <p>
 * 例子
 * <p>
 * CommonLogger logger=CommonLogFactory.getLogger(CommonLogFactory.class);
 * <p>
 * logger.info("");
 */
public class CommonLogFactory {
    @SuppressWarnings("rawtypes")
    public static CommonLogger getLogger(Class c) {
        return new CommonLogger(c);
    }
}
