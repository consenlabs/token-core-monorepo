package im.imkey.imkeylibrary.exception;

public class ImkeyException extends RuntimeException {



    public ImkeyException(String message){
        super(message);
    }

    public ImkeyException(String message, Throwable throwable) {
        super(message, throwable);
    }


    public ImkeyException(Throwable throwable) {
        super(throwable);
    }

    @Override
    public String toString() {
        return getMessage();
    }
}
