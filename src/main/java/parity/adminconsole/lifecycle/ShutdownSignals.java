package parity.adminconsole.lifecycle;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * {@code SIGTERM} and {@code SIGINT} (ARCH §7.3), handled from the first line of {@code main},
 * before the application starts:
 * <ul>
 *   <li><b>the first</b> closes the context, which drains ({@link LifecycleFiles}), then exits
 *       0 if the drain finished in time and 1 if not. If it arrives while the application is
 *       still starting, no healthy file is ever written ({@link #requested()}), and the drain
 *       runs as soon as the start is done: exit 0 with a drained file, as for any drain;</li>
 *   <li><b>a second</b> ends the process at once with 128 + the signal's number (143 for
 *       {@code TERM}, 130 for {@code INT}), with no drained file.</li>
 * </ul>
 * The handlers are installed through {@code sun.misc.Signal} (module {@code jdk.unsupported}),
 * reached by reflection so the build's {@code -Werror} doesn't trip on the "proprietary API"
 * warning a direct reference gives.
 */
public final class ShutdownSignals {

    private static final Logger log = LoggerFactory.getLogger(ShutdownSignals.class);
    private static final AtomicBoolean REQUESTED = new AtomicBoolean();
    private static final AtomicBoolean SHUTDOWN_STARTED = new AtomicBoolean();
    private static final AtomicReference<ConfigurableApplicationContext> CONTEXT = new AtomicReference<>();

    private ShutdownSignals() {}

    /** True once a first signal arrived: no healthy file may be written from then on. */
    public static boolean requested() {
        return REQUESTED.get();
    }

    /** Installs the handlers. Called before the application starts. */
    public static void install() {
        try {
            Class<?> signalClass = Class.forName("sun.misc.Signal");
            Class<?> handlerClass = Class.forName("sun.misc.SignalHandler");
            Method handle = signalClass.getMethod("handle", signalClass, handlerClass);
            Method getNumber = signalClass.getMethod("getNumber");
            Method getName = signalClass.getMethod("getName");
            InvocationHandler onSignal = (proxy, method, args) -> {
                if ("handle".equals(method.getName()) && args != null && args.length == 1) {
                    received((String) getName.invoke(args[0]), (int) getNumber.invoke(args[0]));
                    return null;
                }
                return switch (method.getName()) {
                    case "toString" -> "parity shutdown signal handler";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> identical(proxy, args[0]);
                    default -> null;
                };
            };
            Object handler = Proxy.newProxyInstance(handlerClass.getClassLoader(), new Class<?>[] {handlerClass}, onSignal);
            for (String name : new String[] {"TERM", "INT"}) {
                handle.invoke(null, signalClass.getConstructor(String.class).newInstance(name), handler);
            }
        } catch (ReflectiveOperationException e) {
            // Without the handlers the JVM's own SIGTERM handling still closes the context (and
            // drains) through Spring Boot's shutdown hook; only the exit codes differ.
            line("WARN", "signal handlers not installed", "\"error\":\"" + e.getClass().getSimpleName() + "\"");
        }
    }

    /** The application has started: drain now if a signal came during the start. */
    public static void started(ConfigurableApplicationContext context) {
        CONTEXT.set(context);
        shutdownIfRequested();
    }

    private static void received(String name, int number) {
        if (!REQUESTED.compareAndSet(false, true)) {
            int code = ExitCodes.forSignal(number);
            // The async log appender won't get to flush: one plain line, written directly.
            line("WARN", "a second signal: ending at once, no drained file",
                    "\"signal\":\"" + name + "\",\"exit_code\":" + code);
            Runtime.getRuntime().halt(code);
            return;
        }
        if (CONTEXT.get() == null) {
            // Logging may not be set up yet: a plain line.
            line("INFO", "a signal during the start: no healthy file; the drain runs once started",
                    "\"signal\":\"" + name + "\"");
        } else {
            log.atInfo().addKeyValue("signal", name).addKeyValue("event", "service.draining").log("shutting down: draining");
        }
        shutdownIfRequested();
    }

    private static void shutdownIfRequested() {
        ConfigurableApplicationContext context = CONTEXT.get();
        if (context == null || !REQUESTED.get() || !SHUTDOWN_STARTED.compareAndSet(false, true)) {
            return;
        }
        LifecycleFiles files = context.getBean(LifecycleFiles.class);
        // Not a daemon (a signal handler's thread is one, and its children inherit that): the JVM
        // must not end on its own, with 0, once the closed context leaves no other thread.
        Thread.ofPlatform().name("shutdown").daemon(false).start(() -> {
            int code;
            try {
                context.close();
                code = files.outcome() == LifecycleFiles.Outcome.DRAINED ? ExitCodes.DRAINED : ExitCodes.FAILED;
            } catch (RuntimeException e) {
                log.atError().addKeyValue("cause", e.getClass().getSimpleName()).addKeyValue("event", "lifecycle.drain_failed").log("the drain failed");
                code = ExitCodes.FAILED;
            }
            System.exit(code);
        });
    }

    /** One JSON line straight to stdout, for when the logging system can't be used. */
    private static void line(String level, String message, String fields) {
        System.out.println("{\"ts\":\"" + Instant.now() + "\",\"level\":\"" + level + "\",\"target\":\""
                + ShutdownSignals.class.getName() + "\",\"message\":\"" + message
                + "\",\"service\":\"parity-admin-console\"," + fields + "}");
        System.out.flush();
    }

    /** A proxy is equal only to itself. */
    @SuppressWarnings("ReferenceEquality")
    private static boolean identical(Object a, Object b) {
        return a == b;
    }
}
