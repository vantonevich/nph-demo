package com.nextpathway.jsvc.wrapper;

import java.util.Arrays;

import org.apache.commons.daemon.Daemon;
import org.apache.commons.daemon.DaemonContext;
import org.apache.commons.daemon.DaemonController;


/**
 * Hello jsvc
 *
 */
public class App implements DaemonContext, DaemonController
{
	private Thread shutdownHook;
	private final String[] args;
	Daemon daemon;
	private final Object completionSemaphore;

	App(String[] args) {
		this.args = args;
		completionSemaphore = App.class;
	}

	private void started(Daemon daemon) {
		this.daemon = daemon;
		shutdownHook = new Thread(() -> {shutdown();});
		Runtime.getRuntime().addShutdownHook(shutdownHook);
	}

	private void waitCompletion() {
		synchronized (completionSemaphore) {
			try {
				completionSemaphore.wait();
			} catch (InterruptedException e) {
				System.err.println("Completion wait has been interrupted");
			}
		}
	}

	public static void main( String[] args )
	{
		if (args == null || args.length == 0) {
			System.err.println("No arguments supplied ");
			System.exit(/*status:*/1);
		}
		String daemonClassName = args[0];
		Class<?> daemonClass;
		try {
			daemonClass = App.class.getClassLoader().loadClass(daemonClassName);
		} catch (ClassNotFoundException e) {
			System.err.println("Cannot load class " + daemonClassName);
			e.printStackTrace(System.err);
			System.exit(/*status:*/2);
			return; // NOT reachable
		}
		System.err.println("Initializing daemon");
		Daemon daemon;
		try {
			daemon = (Daemon)daemonClass.newInstance();
		} catch (InstantiationException | IllegalAccessException e) {
			System.err.println("Cannot instantite daemon wrapper " + daemonClassName);
			e.printStackTrace(System.err);
			System.exit(/*status:*/3);
			return; // NOT reachable
		}

		String[] appArgs;
		if (args.length == 1) {
			appArgs = null;
		} else {
			appArgs = Arrays.copyOfRange(args, 1, args.length - 1);
		}
		System.err.println("JSVC arguments:" + Arrays.toString(appArgs));
		App app = new App(appArgs);
		try {
			daemon.init(/*context:*/app);
		} catch (Exception e) {
			System.err.println("Daemon wrapper failed to initalize:" + daemonClassName);
			e.printStackTrace(System.err);
			System.exit(/*status:*/4);
		}
		System.err.println("Init completed, starting ...");
		try {
			daemon.start();
		} catch (Throwable e) {
			System.err.println("Daemon wrapper failed to start.");
			e.printStackTrace(System.err);
			daemon.destroy();
			System.exit(/*status:*/5);
		}
		System.err.println("Start completed, setting shutdown hook..");
		app.started(daemon);
		System.out.println("Initialization completed, processing...");
		app.waitCompletion();
		System.out.println("Exiting...");
	}

	@Override
	public DaemonController getController() {
		return this;
	}

	@Override
	public String[] getArguments() {
		return args;
	}

	@Override
	public void shutdown() throws IllegalStateException {
		System.out.println("Shutdown requested");
		if (shutdownHook != null) {
			Runtime.getRuntime().removeShutdownHook(shutdownHook);
			shutdownHook = null;
		}
		if (daemon != null) {
			try {
				daemon.stop();
			} catch (Exception e) {
				fail("Failed to stop daemon wrapper");
				e.printStackTrace(System.err);
			}
			daemon.destroy();
			daemon = null;
		}
		synchronized (completionSemaphore) {
			completionSemaphore.notifyAll();
		}
	}

	@Override
	public void reload() throws IllegalStateException {
		throw new IllegalStateException("Not supported");
	}

	@Override
	public void fail() throws IllegalStateException {
		fail("fail() called");
		shutdown();
	}

	@Override
	public void fail(String message) throws IllegalStateException {
		System.err.println(message);
		shutdown();
	}

	@Override
	public void fail(Exception exception) throws IllegalStateException {
		exception.printStackTrace(System.err);
	}

	@Override
	public void fail(String message, Exception exception)
			throws IllegalStateException {
		System.err.println(message);
		exception.printStackTrace(System.err);
		shutdown();
	}
}
