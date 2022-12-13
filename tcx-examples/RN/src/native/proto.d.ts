import * as $protobuf from "protobufjs";
/** Namespace api. */
export namespace api {

    /** Properties of a TcxAction. */
    interface ITcxAction {

        /** TcxAction method */
        method?: (string|null);

        /** TcxAction param */
        param?: (google.protobuf.IAny|null);
    }

    /** Represents a TcxAction. */
    class TcxAction implements ITcxAction {

        /**
         * Constructs a new TcxAction.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.ITcxAction);

        /** TcxAction method. */
        public method: string;

        /** TcxAction param. */
        public param?: (google.protobuf.IAny|null);

        /**
         * Creates a new TcxAction instance using the specified properties.
         * @param [properties] Properties to set
         * @returns TcxAction instance
         */
        public static create(properties?: api.ITcxAction): api.TcxAction;

        /**
         * Encodes the specified TcxAction message. Does not implicitly {@link api.TcxAction.verify|verify} messages.
         * @param message TcxAction message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.ITcxAction, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified TcxAction message, length delimited. Does not implicitly {@link api.TcxAction.verify|verify} messages.
         * @param message TcxAction message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.ITcxAction, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a TcxAction message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns TcxAction
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.TcxAction;

        /**
         * Decodes a TcxAction message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns TcxAction
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.TcxAction;

        /**
         * Verifies a TcxAction message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a TcxAction message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns TcxAction
         */
        public static fromObject(object: { [k: string]: any }): api.TcxAction;

        /**
         * Creates a plain object from a TcxAction message. Also converts values to other types if specified.
         * @param message TcxAction
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.TcxAction, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this TcxAction to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a Response. */
    interface IResponse {

        /** Response isSuccess */
        isSuccess?: (boolean|null);

        /** Response error */
        error?: (string|null);
    }

    /** Represents a Response. */
    class Response implements IResponse {

        /**
         * Constructs a new Response.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IResponse);

        /** Response isSuccess. */
        public isSuccess: boolean;

        /** Response error. */
        public error: string;

        /**
         * Creates a new Response instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Response instance
         */
        public static create(properties?: api.IResponse): api.Response;

        /**
         * Encodes the specified Response message. Does not implicitly {@link api.Response.verify|verify} messages.
         * @param message Response message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IResponse, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified Response message, length delimited. Does not implicitly {@link api.Response.verify|verify} messages.
         * @param message Response message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IResponse, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a Response message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns Response
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.Response;

        /**
         * Decodes a Response message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns Response
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.Response;

        /**
         * Verifies a Response message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a Response message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns Response
         */
        public static fromObject(object: { [k: string]: any }): api.Response;

        /**
         * Creates a plain object from a Response message. Also converts values to other types if specified.
         * @param message Response
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.Response, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this Response to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of an InitTokenCoreXParam. */
    interface IInitTokenCoreXParam {

        /** InitTokenCoreXParam fileDir */
        fileDir?: (string|null);

        /** InitTokenCoreXParam xpubCommonKey */
        xpubCommonKey?: (string|null);

        /** InitTokenCoreXParam xpubCommonIv */
        xpubCommonIv?: (string|null);

        /** InitTokenCoreXParam isDebug */
        isDebug?: (boolean|null);
    }

    /** Represents an InitTokenCoreXParam. */
    class InitTokenCoreXParam implements IInitTokenCoreXParam {

        /**
         * Constructs a new InitTokenCoreXParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IInitTokenCoreXParam);

        /** InitTokenCoreXParam fileDir. */
        public fileDir: string;

        /** InitTokenCoreXParam xpubCommonKey. */
        public xpubCommonKey: string;

        /** InitTokenCoreXParam xpubCommonIv. */
        public xpubCommonIv: string;

        /** InitTokenCoreXParam isDebug. */
        public isDebug: boolean;

        /**
         * Creates a new InitTokenCoreXParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns InitTokenCoreXParam instance
         */
        public static create(properties?: api.IInitTokenCoreXParam): api.InitTokenCoreXParam;

        /**
         * Encodes the specified InitTokenCoreXParam message. Does not implicitly {@link api.InitTokenCoreXParam.verify|verify} messages.
         * @param message InitTokenCoreXParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IInitTokenCoreXParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified InitTokenCoreXParam message, length delimited. Does not implicitly {@link api.InitTokenCoreXParam.verify|verify} messages.
         * @param message InitTokenCoreXParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IInitTokenCoreXParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an InitTokenCoreXParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns InitTokenCoreXParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.InitTokenCoreXParam;

        /**
         * Decodes an InitTokenCoreXParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns InitTokenCoreXParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.InitTokenCoreXParam;

        /**
         * Verifies an InitTokenCoreXParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an InitTokenCoreXParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns InitTokenCoreXParam
         */
        public static fromObject(object: { [k: string]: any }): api.InitTokenCoreXParam;

        /**
         * Creates a plain object from an InitTokenCoreXParam message. Also converts values to other types if specified.
         * @param message InitTokenCoreXParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.InitTokenCoreXParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this InitTokenCoreXParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of an ExportPrivateKeyParam. */
    interface IExportPrivateKeyParam {

        /** ExportPrivateKeyParam id */
        id?: (string|null);

        /** ExportPrivateKeyParam password */
        password?: (string|null);

        /** ExportPrivateKeyParam chainType */
        chainType?: (string|null);

        /** ExportPrivateKeyParam network */
        network?: (string|null);

        /** ExportPrivateKeyParam mainAddress */
        mainAddress?: (string|null);

        /** ExportPrivateKeyParam path */
        path?: (string|null);
    }

    /** export the private key from a private key keystore or a hd keystore */
    class ExportPrivateKeyParam implements IExportPrivateKeyParam {

        /**
         * Constructs a new ExportPrivateKeyParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IExportPrivateKeyParam);

        /** ExportPrivateKeyParam id. */
        public id: string;

        /** ExportPrivateKeyParam password. */
        public password: string;

        /** ExportPrivateKeyParam chainType. */
        public chainType: string;

        /** ExportPrivateKeyParam network. */
        public network: string;

        /** ExportPrivateKeyParam mainAddress. */
        public mainAddress: string;

        /** ExportPrivateKeyParam path. */
        public path: string;

        /**
         * Creates a new ExportPrivateKeyParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns ExportPrivateKeyParam instance
         */
        public static create(properties?: api.IExportPrivateKeyParam): api.ExportPrivateKeyParam;

        /**
         * Encodes the specified ExportPrivateKeyParam message. Does not implicitly {@link api.ExportPrivateKeyParam.verify|verify} messages.
         * @param message ExportPrivateKeyParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IExportPrivateKeyParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified ExportPrivateKeyParam message, length delimited. Does not implicitly {@link api.ExportPrivateKeyParam.verify|verify} messages.
         * @param message ExportPrivateKeyParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IExportPrivateKeyParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an ExportPrivateKeyParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns ExportPrivateKeyParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.ExportPrivateKeyParam;

        /**
         * Decodes an ExportPrivateKeyParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns ExportPrivateKeyParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.ExportPrivateKeyParam;

        /**
         * Verifies an ExportPrivateKeyParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an ExportPrivateKeyParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns ExportPrivateKeyParam
         */
        public static fromObject(object: { [k: string]: any }): api.ExportPrivateKeyParam;

        /**
         * Creates a plain object from an ExportPrivateKeyParam message. Also converts values to other types if specified.
         * @param message ExportPrivateKeyParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.ExportPrivateKeyParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this ExportPrivateKeyParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a WalletKeyParam. */
    interface IWalletKeyParam {

        /** WalletKeyParam id */
        id?: (string|null);

        /** WalletKeyParam password */
        password?: (string|null);
    }

    /** verify the password of the keystore */
    class WalletKeyParam implements IWalletKeyParam {

        /**
         * Constructs a new WalletKeyParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IWalletKeyParam);

        /** WalletKeyParam id. */
        public id: string;

        /** WalletKeyParam password. */
        public password: string;

        /**
         * Creates a new WalletKeyParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns WalletKeyParam instance
         */
        public static create(properties?: api.IWalletKeyParam): api.WalletKeyParam;

        /**
         * Encodes the specified WalletKeyParam message. Does not implicitly {@link api.WalletKeyParam.verify|verify} messages.
         * @param message WalletKeyParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IWalletKeyParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified WalletKeyParam message, length delimited. Does not implicitly {@link api.WalletKeyParam.verify|verify} messages.
         * @param message WalletKeyParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IWalletKeyParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a WalletKeyParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns WalletKeyParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.WalletKeyParam;

        /**
         * Decodes a WalletKeyParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns WalletKeyParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.WalletKeyParam;

        /**
         * Verifies a WalletKeyParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a WalletKeyParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns WalletKeyParam
         */
        public static fromObject(object: { [k: string]: any }): api.WalletKeyParam;

        /**
         * Creates a plain object from a WalletKeyParam message. Also converts values to other types if specified.
         * @param message WalletKeyParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.WalletKeyParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this WalletKeyParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a VerifyDerivedKeyParam. */
    interface IVerifyDerivedKeyParam {

        /** VerifyDerivedKeyParam id */
        id?: (string|null);

        /** VerifyDerivedKeyParam derivedKey */
        derivedKey?: (string|null);
    }

    /** Represents a VerifyDerivedKeyParam. */
    class VerifyDerivedKeyParam implements IVerifyDerivedKeyParam {

        /**
         * Constructs a new VerifyDerivedKeyParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IVerifyDerivedKeyParam);

        /** VerifyDerivedKeyParam id. */
        public id: string;

        /** VerifyDerivedKeyParam derivedKey. */
        public derivedKey: string;

        /**
         * Creates a new VerifyDerivedKeyParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns VerifyDerivedKeyParam instance
         */
        public static create(properties?: api.IVerifyDerivedKeyParam): api.VerifyDerivedKeyParam;

        /**
         * Encodes the specified VerifyDerivedKeyParam message. Does not implicitly {@link api.VerifyDerivedKeyParam.verify|verify} messages.
         * @param message VerifyDerivedKeyParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IVerifyDerivedKeyParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified VerifyDerivedKeyParam message, length delimited. Does not implicitly {@link api.VerifyDerivedKeyParam.verify|verify} messages.
         * @param message VerifyDerivedKeyParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IVerifyDerivedKeyParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a VerifyDerivedKeyParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns VerifyDerivedKeyParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.VerifyDerivedKeyParam;

        /**
         * Decodes a VerifyDerivedKeyParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns VerifyDerivedKeyParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.VerifyDerivedKeyParam;

        /**
         * Verifies a VerifyDerivedKeyParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a VerifyDerivedKeyParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns VerifyDerivedKeyParam
         */
        public static fromObject(object: { [k: string]: any }): api.VerifyDerivedKeyParam;

        /**
         * Creates a plain object from a VerifyDerivedKeyParam message. Also converts values to other types if specified.
         * @param message VerifyDerivedKeyParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.VerifyDerivedKeyParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this VerifyDerivedKeyParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a DerivedKeyResult. */
    interface IDerivedKeyResult {

        /** DerivedKeyResult id */
        id?: (string|null);

        /** DerivedKeyResult derivedKey */
        derivedKey?: (string|null);
    }

    /** Represents a DerivedKeyResult. */
    class DerivedKeyResult implements IDerivedKeyResult {

        /**
         * Constructs a new DerivedKeyResult.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IDerivedKeyResult);

        /** DerivedKeyResult id. */
        public id: string;

        /** DerivedKeyResult derivedKey. */
        public derivedKey: string;

        /**
         * Creates a new DerivedKeyResult instance using the specified properties.
         * @param [properties] Properties to set
         * @returns DerivedKeyResult instance
         */
        public static create(properties?: api.IDerivedKeyResult): api.DerivedKeyResult;

        /**
         * Encodes the specified DerivedKeyResult message. Does not implicitly {@link api.DerivedKeyResult.verify|verify} messages.
         * @param message DerivedKeyResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IDerivedKeyResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified DerivedKeyResult message, length delimited. Does not implicitly {@link api.DerivedKeyResult.verify|verify} messages.
         * @param message DerivedKeyResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IDerivedKeyResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a DerivedKeyResult message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns DerivedKeyResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.DerivedKeyResult;

        /**
         * Decodes a DerivedKeyResult message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns DerivedKeyResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.DerivedKeyResult;

        /**
         * Verifies a DerivedKeyResult message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a DerivedKeyResult message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns DerivedKeyResult
         */
        public static fromObject(object: { [k: string]: any }): api.DerivedKeyResult;

        /**
         * Creates a plain object from a DerivedKeyResult message. Also converts values to other types if specified.
         * @param message DerivedKeyResult
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.DerivedKeyResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this DerivedKeyResult to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a CacheDerivedKeyResult. */
    interface ICacheDerivedKeyResult {

        /** CacheDerivedKeyResult id */
        id?: (string|null);

        /** CacheDerivedKeyResult enableDerivedKey */
        enableDerivedKey?: (boolean|null);

        /** CacheDerivedKeyResult mode */
        mode?: (string|null);
    }

    /** Represents a CacheDerivedKeyResult. */
    class CacheDerivedKeyResult implements ICacheDerivedKeyResult {

        /**
         * Constructs a new CacheDerivedKeyResult.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.ICacheDerivedKeyResult);

        /** CacheDerivedKeyResult id. */
        public id: string;

        /** CacheDerivedKeyResult enableDerivedKey. */
        public enableDerivedKey: boolean;

        /** CacheDerivedKeyResult mode. */
        public mode: string;

        /**
         * Creates a new CacheDerivedKeyResult instance using the specified properties.
         * @param [properties] Properties to set
         * @returns CacheDerivedKeyResult instance
         */
        public static create(properties?: api.ICacheDerivedKeyResult): api.CacheDerivedKeyResult;

        /**
         * Encodes the specified CacheDerivedKeyResult message. Does not implicitly {@link api.CacheDerivedKeyResult.verify|verify} messages.
         * @param message CacheDerivedKeyResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.ICacheDerivedKeyResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified CacheDerivedKeyResult message, length delimited. Does not implicitly {@link api.CacheDerivedKeyResult.verify|verify} messages.
         * @param message CacheDerivedKeyResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.ICacheDerivedKeyResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a CacheDerivedKeyResult message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns CacheDerivedKeyResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.CacheDerivedKeyResult;

        /**
         * Decodes a CacheDerivedKeyResult message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns CacheDerivedKeyResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.CacheDerivedKeyResult;

        /**
         * Verifies a CacheDerivedKeyResult message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a CacheDerivedKeyResult message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns CacheDerivedKeyResult
         */
        public static fromObject(object: { [k: string]: any }): api.CacheDerivedKeyResult;

        /**
         * Creates a plain object from a CacheDerivedKeyResult message. Also converts values to other types if specified.
         * @param message CacheDerivedKeyResult
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.CacheDerivedKeyResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this CacheDerivedKeyResult to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a WalletId. */
    interface IWalletId {

        /** WalletId id */
        id?: (string|null);
    }

    /** Represents a WalletId. */
    class WalletId implements IWalletId {

        /**
         * Constructs a new WalletId.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IWalletId);

        /** WalletId id. */
        public id: string;

        /**
         * Creates a new WalletId instance using the specified properties.
         * @param [properties] Properties to set
         * @returns WalletId instance
         */
        public static create(properties?: api.IWalletId): api.WalletId;

        /**
         * Encodes the specified WalletId message. Does not implicitly {@link api.WalletId.verify|verify} messages.
         * @param message WalletId message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IWalletId, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified WalletId message, length delimited. Does not implicitly {@link api.WalletId.verify|verify} messages.
         * @param message WalletId message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IWalletId, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a WalletId message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns WalletId
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.WalletId;

        /**
         * Decodes a WalletId message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns WalletId
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.WalletId;

        /**
         * Verifies a WalletId message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a WalletId message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns WalletId
         */
        public static fromObject(object: { [k: string]: any }): api.WalletId;

        /**
         * Creates a plain object from a WalletId message. Also converts values to other types if specified.
         * @param message WalletId
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.WalletId, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this WalletId to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a BiometricModeResult. */
    interface IBiometricModeResult {

        /** BiometricModeResult mode */
        mode?: (string|null);
    }

    /** Represents a BiometricModeResult. */
    class BiometricModeResult implements IBiometricModeResult {

        /**
         * Constructs a new BiometricModeResult.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IBiometricModeResult);

        /** BiometricModeResult mode. */
        public mode: string;

        /**
         * Creates a new BiometricModeResult instance using the specified properties.
         * @param [properties] Properties to set
         * @returns BiometricModeResult instance
         */
        public static create(properties?: api.IBiometricModeResult): api.BiometricModeResult;

        /**
         * Encodes the specified BiometricModeResult message. Does not implicitly {@link api.BiometricModeResult.verify|verify} messages.
         * @param message BiometricModeResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IBiometricModeResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified BiometricModeResult message, length delimited. Does not implicitly {@link api.BiometricModeResult.verify|verify} messages.
         * @param message BiometricModeResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IBiometricModeResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a BiometricModeResult message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns BiometricModeResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.BiometricModeResult;

        /**
         * Decodes a BiometricModeResult message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns BiometricModeResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.BiometricModeResult;

        /**
         * Verifies a BiometricModeResult message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a BiometricModeResult message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns BiometricModeResult
         */
        public static fromObject(object: { [k: string]: any }): api.BiometricModeResult;

        /**
         * Creates a plain object from a BiometricModeResult message. Also converts values to other types if specified.
         * @param message BiometricModeResult
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.BiometricModeResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this BiometricModeResult to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a HdStoreCreateParam. */
    interface IHdStoreCreateParam {

        /** HdStoreCreateParam password */
        password?: (string|null);

        /** HdStoreCreateParam passwordHint */
        passwordHint?: (string|null);

        /** HdStoreCreateParam name */
        name?: (string|null);
    }

    /** Represents a HdStoreCreateParam. */
    class HdStoreCreateParam implements IHdStoreCreateParam {

        /**
         * Constructs a new HdStoreCreateParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IHdStoreCreateParam);

        /** HdStoreCreateParam password. */
        public password: string;

        /** HdStoreCreateParam passwordHint. */
        public passwordHint: string;

        /** HdStoreCreateParam name. */
        public name: string;

        /**
         * Creates a new HdStoreCreateParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns HdStoreCreateParam instance
         */
        public static create(properties?: api.IHdStoreCreateParam): api.HdStoreCreateParam;

        /**
         * Encodes the specified HdStoreCreateParam message. Does not implicitly {@link api.HdStoreCreateParam.verify|verify} messages.
         * @param message HdStoreCreateParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IHdStoreCreateParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified HdStoreCreateParam message, length delimited. Does not implicitly {@link api.HdStoreCreateParam.verify|verify} messages.
         * @param message HdStoreCreateParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IHdStoreCreateParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a HdStoreCreateParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns HdStoreCreateParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.HdStoreCreateParam;

        /**
         * Decodes a HdStoreCreateParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns HdStoreCreateParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.HdStoreCreateParam;

        /**
         * Verifies a HdStoreCreateParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a HdStoreCreateParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns HdStoreCreateParam
         */
        public static fromObject(object: { [k: string]: any }): api.HdStoreCreateParam;

        /**
         * Creates a plain object from a HdStoreCreateParam message. Also converts values to other types if specified.
         * @param message HdStoreCreateParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.HdStoreCreateParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this HdStoreCreateParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a WalletResult. */
    interface IWalletResult {

        /** WalletResult id */
        id?: (string|null);

        /** WalletResult name */
        name?: (string|null);

        /** WalletResult source */
        source?: (string|null);

        /** WalletResult accounts */
        accounts?: (api.IAccountResponse[]|null);

        /** WalletResult createdAt */
        createdAt?: (number|Long|null);
    }

    /** Represents a WalletResult. */
    class WalletResult implements IWalletResult {

        /**
         * Constructs a new WalletResult.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IWalletResult);

        /** WalletResult id. */
        public id: string;

        /** WalletResult name. */
        public name: string;

        /** WalletResult source. */
        public source: string;

        /** WalletResult accounts. */
        public accounts: api.IAccountResponse[];

        /** WalletResult createdAt. */
        public createdAt: (number|Long);

        /**
         * Creates a new WalletResult instance using the specified properties.
         * @param [properties] Properties to set
         * @returns WalletResult instance
         */
        public static create(properties?: api.IWalletResult): api.WalletResult;

        /**
         * Encodes the specified WalletResult message. Does not implicitly {@link api.WalletResult.verify|verify} messages.
         * @param message WalletResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IWalletResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified WalletResult message, length delimited. Does not implicitly {@link api.WalletResult.verify|verify} messages.
         * @param message WalletResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IWalletResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a WalletResult message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns WalletResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.WalletResult;

        /**
         * Decodes a WalletResult message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns WalletResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.WalletResult;

        /**
         * Verifies a WalletResult message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a WalletResult message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns WalletResult
         */
        public static fromObject(object: { [k: string]: any }): api.WalletResult;

        /**
         * Creates a plain object from a WalletResult message. Also converts values to other types if specified.
         * @param message WalletResult
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.WalletResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this WalletResult to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a HdStoreImportParam. */
    interface IHdStoreImportParam {

        /** HdStoreImportParam mnemonic */
        mnemonic?: (string|null);

        /** HdStoreImportParam password */
        password?: (string|null);

        /** HdStoreImportParam source */
        source?: (string|null);

        /** HdStoreImportParam name */
        name?: (string|null);

        /** HdStoreImportParam passwordHint */
        passwordHint?: (string|null);

        /** HdStoreImportParam overwrite */
        overwrite?: (boolean|null);
    }

    /** Represents a HdStoreImportParam. */
    class HdStoreImportParam implements IHdStoreImportParam {

        /**
         * Constructs a new HdStoreImportParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IHdStoreImportParam);

        /** HdStoreImportParam mnemonic. */
        public mnemonic: string;

        /** HdStoreImportParam password. */
        public password: string;

        /** HdStoreImportParam source. */
        public source: string;

        /** HdStoreImportParam name. */
        public name: string;

        /** HdStoreImportParam passwordHint. */
        public passwordHint: string;

        /** HdStoreImportParam overwrite. */
        public overwrite: boolean;

        /**
         * Creates a new HdStoreImportParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns HdStoreImportParam instance
         */
        public static create(properties?: api.IHdStoreImportParam): api.HdStoreImportParam;

        /**
         * Encodes the specified HdStoreImportParam message. Does not implicitly {@link api.HdStoreImportParam.verify|verify} messages.
         * @param message HdStoreImportParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IHdStoreImportParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified HdStoreImportParam message, length delimited. Does not implicitly {@link api.HdStoreImportParam.verify|verify} messages.
         * @param message HdStoreImportParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IHdStoreImportParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a HdStoreImportParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns HdStoreImportParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.HdStoreImportParam;

        /**
         * Decodes a HdStoreImportParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns HdStoreImportParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.HdStoreImportParam;

        /**
         * Verifies a HdStoreImportParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a HdStoreImportParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns HdStoreImportParam
         */
        public static fromObject(object: { [k: string]: any }): api.HdStoreImportParam;

        /**
         * Creates a plain object from a HdStoreImportParam message. Also converts values to other types if specified.
         * @param message HdStoreImportParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.HdStoreImportParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this HdStoreImportParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a KeystoreCommonDeriveParam. */
    interface IKeystoreCommonDeriveParam {

        /** KeystoreCommonDeriveParam id */
        id?: (string|null);

        /** KeystoreCommonDeriveParam password */
        password?: (string|null);

        /** KeystoreCommonDeriveParam derivations */
        derivations?: (api.KeystoreCommonDeriveParam.IDerivation[]|null);
    }

    /** Represents a KeystoreCommonDeriveParam. */
    class KeystoreCommonDeriveParam implements IKeystoreCommonDeriveParam {

        /**
         * Constructs a new KeystoreCommonDeriveParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IKeystoreCommonDeriveParam);

        /** KeystoreCommonDeriveParam id. */
        public id: string;

        /** KeystoreCommonDeriveParam password. */
        public password: string;

        /** KeystoreCommonDeriveParam derivations. */
        public derivations: api.KeystoreCommonDeriveParam.IDerivation[];

        /**
         * Creates a new KeystoreCommonDeriveParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns KeystoreCommonDeriveParam instance
         */
        public static create(properties?: api.IKeystoreCommonDeriveParam): api.KeystoreCommonDeriveParam;

        /**
         * Encodes the specified KeystoreCommonDeriveParam message. Does not implicitly {@link api.KeystoreCommonDeriveParam.verify|verify} messages.
         * @param message KeystoreCommonDeriveParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IKeystoreCommonDeriveParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified KeystoreCommonDeriveParam message, length delimited. Does not implicitly {@link api.KeystoreCommonDeriveParam.verify|verify} messages.
         * @param message KeystoreCommonDeriveParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IKeystoreCommonDeriveParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a KeystoreCommonDeriveParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns KeystoreCommonDeriveParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.KeystoreCommonDeriveParam;

        /**
         * Decodes a KeystoreCommonDeriveParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns KeystoreCommonDeriveParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.KeystoreCommonDeriveParam;

        /**
         * Verifies a KeystoreCommonDeriveParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a KeystoreCommonDeriveParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns KeystoreCommonDeriveParam
         */
        public static fromObject(object: { [k: string]: any }): api.KeystoreCommonDeriveParam;

        /**
         * Creates a plain object from a KeystoreCommonDeriveParam message. Also converts values to other types if specified.
         * @param message KeystoreCommonDeriveParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.KeystoreCommonDeriveParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this KeystoreCommonDeriveParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    namespace KeystoreCommonDeriveParam {

        /** Properties of a Derivation. */
        interface IDerivation {

            /** Derivation chainType */
            chainType?: (string|null);

            /** Derivation path */
            path?: (string|null);

            /** Derivation network */
            network?: (string|null);

            /** Derivation segWit */
            segWit?: (string|null);

            /** Derivation chainId */
            chainId?: (string|null);
        }

        /** Represents a Derivation. */
        class Derivation implements IDerivation {

            /**
             * Constructs a new Derivation.
             * @param [properties] Properties to set
             */
            constructor(properties?: api.KeystoreCommonDeriveParam.IDerivation);

            /** Derivation chainType. */
            public chainType: string;

            /** Derivation path. */
            public path: string;

            /** Derivation network. */
            public network: string;

            /** Derivation segWit. */
            public segWit: string;

            /** Derivation chainId. */
            public chainId: string;

            /**
             * Creates a new Derivation instance using the specified properties.
             * @param [properties] Properties to set
             * @returns Derivation instance
             */
            public static create(properties?: api.KeystoreCommonDeriveParam.IDerivation): api.KeystoreCommonDeriveParam.Derivation;

            /**
             * Encodes the specified Derivation message. Does not implicitly {@link api.KeystoreCommonDeriveParam.Derivation.verify|verify} messages.
             * @param message Derivation message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: api.KeystoreCommonDeriveParam.IDerivation, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified Derivation message, length delimited. Does not implicitly {@link api.KeystoreCommonDeriveParam.Derivation.verify|verify} messages.
             * @param message Derivation message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: api.KeystoreCommonDeriveParam.IDerivation, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a Derivation message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns Derivation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.KeystoreCommonDeriveParam.Derivation;

            /**
             * Decodes a Derivation message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns Derivation
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.KeystoreCommonDeriveParam.Derivation;

            /**
             * Verifies a Derivation message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a Derivation message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns Derivation
             */
            public static fromObject(object: { [k: string]: any }): api.KeystoreCommonDeriveParam.Derivation;

            /**
             * Creates a plain object from a Derivation message. Also converts values to other types if specified.
             * @param message Derivation
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: api.KeystoreCommonDeriveParam.Derivation, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this Derivation to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };
        }
    }

    /** Properties of an AccountResponse. */
    interface IAccountResponse {

        /** AccountResponse chainType */
        chainType?: (string|null);

        /** AccountResponse address */
        address?: (string|null);

        /** AccountResponse path */
        path?: (string|null);

        /** AccountResponse extendedXpubKey */
        extendedXpubKey?: (string|null);
    }

    /** Represents an AccountResponse. */
    class AccountResponse implements IAccountResponse {

        /**
         * Constructs a new AccountResponse.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IAccountResponse);

        /** AccountResponse chainType. */
        public chainType: string;

        /** AccountResponse address. */
        public address: string;

        /** AccountResponse path. */
        public path: string;

        /** AccountResponse extendedXpubKey. */
        public extendedXpubKey: string;

        /**
         * Creates a new AccountResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns AccountResponse instance
         */
        public static create(properties?: api.IAccountResponse): api.AccountResponse;

        /**
         * Encodes the specified AccountResponse message. Does not implicitly {@link api.AccountResponse.verify|verify} messages.
         * @param message AccountResponse message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IAccountResponse, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified AccountResponse message, length delimited. Does not implicitly {@link api.AccountResponse.verify|verify} messages.
         * @param message AccountResponse message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IAccountResponse, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an AccountResponse message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns AccountResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.AccountResponse;

        /**
         * Decodes an AccountResponse message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns AccountResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.AccountResponse;

        /**
         * Verifies an AccountResponse message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an AccountResponse message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns AccountResponse
         */
        public static fromObject(object: { [k: string]: any }): api.AccountResponse;

        /**
         * Creates a plain object from an AccountResponse message. Also converts values to other types if specified.
         * @param message AccountResponse
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.AccountResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this AccountResponse to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of an AccountsResponse. */
    interface IAccountsResponse {

        /** AccountsResponse accounts */
        accounts?: (api.IAccountResponse[]|null);
    }

    /** Represents an AccountsResponse. */
    class AccountsResponse implements IAccountsResponse {

        /**
         * Constructs a new AccountsResponse.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IAccountsResponse);

        /** AccountsResponse accounts. */
        public accounts: api.IAccountResponse[];

        /**
         * Creates a new AccountsResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns AccountsResponse instance
         */
        public static create(properties?: api.IAccountsResponse): api.AccountsResponse;

        /**
         * Encodes the specified AccountsResponse message. Does not implicitly {@link api.AccountsResponse.verify|verify} messages.
         * @param message AccountsResponse message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IAccountsResponse, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified AccountsResponse message, length delimited. Does not implicitly {@link api.AccountsResponse.verify|verify} messages.
         * @param message AccountsResponse message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IAccountsResponse, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an AccountsResponse message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns AccountsResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.AccountsResponse;

        /**
         * Decodes an AccountsResponse message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns AccountsResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.AccountsResponse;

        /**
         * Verifies an AccountsResponse message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an AccountsResponse message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns AccountsResponse
         */
        public static fromObject(object: { [k: string]: any }): api.AccountsResponse;

        /**
         * Creates a plain object from an AccountsResponse message. Also converts values to other types if specified.
         * @param message AccountsResponse
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.AccountsResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this AccountsResponse to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a KeystoreCommonExportResult. */
    interface IKeystoreCommonExportResult {

        /** KeystoreCommonExportResult id */
        id?: (string|null);

        /** KeystoreCommonExportResult type */
        type?: (api.KeyType|null);

        /** KeystoreCommonExportResult value */
        value?: (string|null);
    }

    /** Represents a KeystoreCommonExportResult. */
    class KeystoreCommonExportResult implements IKeystoreCommonExportResult {

        /**
         * Constructs a new KeystoreCommonExportResult.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IKeystoreCommonExportResult);

        /** KeystoreCommonExportResult id. */
        public id: string;

        /** KeystoreCommonExportResult type. */
        public type: api.KeyType;

        /** KeystoreCommonExportResult value. */
        public value: string;

        /**
         * Creates a new KeystoreCommonExportResult instance using the specified properties.
         * @param [properties] Properties to set
         * @returns KeystoreCommonExportResult instance
         */
        public static create(properties?: api.IKeystoreCommonExportResult): api.KeystoreCommonExportResult;

        /**
         * Encodes the specified KeystoreCommonExportResult message. Does not implicitly {@link api.KeystoreCommonExportResult.verify|verify} messages.
         * @param message KeystoreCommonExportResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IKeystoreCommonExportResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified KeystoreCommonExportResult message, length delimited. Does not implicitly {@link api.KeystoreCommonExportResult.verify|verify} messages.
         * @param message KeystoreCommonExportResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IKeystoreCommonExportResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a KeystoreCommonExportResult message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns KeystoreCommonExportResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.KeystoreCommonExportResult;

        /**
         * Decodes a KeystoreCommonExportResult message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns KeystoreCommonExportResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.KeystoreCommonExportResult;

        /**
         * Verifies a KeystoreCommonExportResult message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a KeystoreCommonExportResult message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns KeystoreCommonExportResult
         */
        public static fromObject(object: { [k: string]: any }): api.KeystoreCommonExportResult;

        /**
         * Creates a plain object from a KeystoreCommonExportResult message. Also converts values to other types if specified.
         * @param message KeystoreCommonExportResult
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.KeystoreCommonExportResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this KeystoreCommonExportResult to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** KeyType enum. */
    enum KeyType {
        MNEMONIC = 0,
        PRIVATE_KEY = 1
    }

    /** Properties of a PrivateKeyStoreImportParam. */
    interface IPrivateKeyStoreImportParam {

        /** PrivateKeyStoreImportParam privateKey */
        privateKey?: (string|null);

        /** PrivateKeyStoreImportParam password */
        password?: (string|null);

        /** PrivateKeyStoreImportParam overwrite */
        overwrite?: (boolean|null);
    }

    /** Represents a PrivateKeyStoreImportParam. */
    class PrivateKeyStoreImportParam implements IPrivateKeyStoreImportParam {

        /**
         * Constructs a new PrivateKeyStoreImportParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IPrivateKeyStoreImportParam);

        /** PrivateKeyStoreImportParam privateKey. */
        public privateKey: string;

        /** PrivateKeyStoreImportParam password. */
        public password: string;

        /** PrivateKeyStoreImportParam overwrite. */
        public overwrite: boolean;

        /**
         * Creates a new PrivateKeyStoreImportParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns PrivateKeyStoreImportParam instance
         */
        public static create(properties?: api.IPrivateKeyStoreImportParam): api.PrivateKeyStoreImportParam;

        /**
         * Encodes the specified PrivateKeyStoreImportParam message. Does not implicitly {@link api.PrivateKeyStoreImportParam.verify|verify} messages.
         * @param message PrivateKeyStoreImportParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IPrivateKeyStoreImportParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified PrivateKeyStoreImportParam message, length delimited. Does not implicitly {@link api.PrivateKeyStoreImportParam.verify|verify} messages.
         * @param message PrivateKeyStoreImportParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IPrivateKeyStoreImportParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a PrivateKeyStoreImportParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns PrivateKeyStoreImportParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.PrivateKeyStoreImportParam;

        /**
         * Decodes a PrivateKeyStoreImportParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns PrivateKeyStoreImportParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.PrivateKeyStoreImportParam;

        /**
         * Verifies a PrivateKeyStoreImportParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a PrivateKeyStoreImportParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns PrivateKeyStoreImportParam
         */
        public static fromObject(object: { [k: string]: any }): api.PrivateKeyStoreImportParam;

        /**
         * Creates a plain object from a PrivateKeyStoreImportParam message. Also converts values to other types if specified.
         * @param message PrivateKeyStoreImportParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.PrivateKeyStoreImportParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this PrivateKeyStoreImportParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a PrivateKeyStoreExportParam. */
    interface IPrivateKeyStoreExportParam {

        /** PrivateKeyStoreExportParam id */
        id?: (string|null);

        /** PrivateKeyStoreExportParam password */
        password?: (string|null);

        /** PrivateKeyStoreExportParam chainType */
        chainType?: (string|null);

        /** PrivateKeyStoreExportParam network */
        network?: (string|null);
    }

    /** Represents a PrivateKeyStoreExportParam. */
    class PrivateKeyStoreExportParam implements IPrivateKeyStoreExportParam {

        /**
         * Constructs a new PrivateKeyStoreExportParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IPrivateKeyStoreExportParam);

        /** PrivateKeyStoreExportParam id. */
        public id: string;

        /** PrivateKeyStoreExportParam password. */
        public password: string;

        /** PrivateKeyStoreExportParam chainType. */
        public chainType: string;

        /** PrivateKeyStoreExportParam network. */
        public network: string;

        /**
         * Creates a new PrivateKeyStoreExportParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns PrivateKeyStoreExportParam instance
         */
        public static create(properties?: api.IPrivateKeyStoreExportParam): api.PrivateKeyStoreExportParam;

        /**
         * Encodes the specified PrivateKeyStoreExportParam message. Does not implicitly {@link api.PrivateKeyStoreExportParam.verify|verify} messages.
         * @param message PrivateKeyStoreExportParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IPrivateKeyStoreExportParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified PrivateKeyStoreExportParam message, length delimited. Does not implicitly {@link api.PrivateKeyStoreExportParam.verify|verify} messages.
         * @param message PrivateKeyStoreExportParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IPrivateKeyStoreExportParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a PrivateKeyStoreExportParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns PrivateKeyStoreExportParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.PrivateKeyStoreExportParam;

        /**
         * Decodes a PrivateKeyStoreExportParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns PrivateKeyStoreExportParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.PrivateKeyStoreExportParam;

        /**
         * Verifies a PrivateKeyStoreExportParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a PrivateKeyStoreExportParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns PrivateKeyStoreExportParam
         */
        public static fromObject(object: { [k: string]: any }): api.PrivateKeyStoreExportParam;

        /**
         * Creates a plain object from a PrivateKeyStoreExportParam message. Also converts values to other types if specified.
         * @param message PrivateKeyStoreExportParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.PrivateKeyStoreExportParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this PrivateKeyStoreExportParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a KeystoreCommonExistsParam. */
    interface IKeystoreCommonExistsParam {

        /** KeystoreCommonExistsParam type */
        type?: (api.KeyType|null);

        /** KeystoreCommonExistsParam value */
        value?: (string|null);
    }

    /** Represents a KeystoreCommonExistsParam. */
    class KeystoreCommonExistsParam implements IKeystoreCommonExistsParam {

        /**
         * Constructs a new KeystoreCommonExistsParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IKeystoreCommonExistsParam);

        /** KeystoreCommonExistsParam type. */
        public type: api.KeyType;

        /** KeystoreCommonExistsParam value. */
        public value: string;

        /**
         * Creates a new KeystoreCommonExistsParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns KeystoreCommonExistsParam instance
         */
        public static create(properties?: api.IKeystoreCommonExistsParam): api.KeystoreCommonExistsParam;

        /**
         * Encodes the specified KeystoreCommonExistsParam message. Does not implicitly {@link api.KeystoreCommonExistsParam.verify|verify} messages.
         * @param message KeystoreCommonExistsParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IKeystoreCommonExistsParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified KeystoreCommonExistsParam message, length delimited. Does not implicitly {@link api.KeystoreCommonExistsParam.verify|verify} messages.
         * @param message KeystoreCommonExistsParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IKeystoreCommonExistsParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a KeystoreCommonExistsParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns KeystoreCommonExistsParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.KeystoreCommonExistsParam;

        /**
         * Decodes a KeystoreCommonExistsParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns KeystoreCommonExistsParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.KeystoreCommonExistsParam;

        /**
         * Verifies a KeystoreCommonExistsParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a KeystoreCommonExistsParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns KeystoreCommonExistsParam
         */
        public static fromObject(object: { [k: string]: any }): api.KeystoreCommonExistsParam;

        /**
         * Creates a plain object from a KeystoreCommonExistsParam message. Also converts values to other types if specified.
         * @param message KeystoreCommonExistsParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.KeystoreCommonExistsParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this KeystoreCommonExistsParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a KeystoreCommonExistsResult. */
    interface IKeystoreCommonExistsResult {

        /** KeystoreCommonExistsResult isExists */
        isExists?: (boolean|null);

        /** KeystoreCommonExistsResult id */
        id?: (string|null);
    }

    /** Represents a KeystoreCommonExistsResult. */
    class KeystoreCommonExistsResult implements IKeystoreCommonExistsResult {

        /**
         * Constructs a new KeystoreCommonExistsResult.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IKeystoreCommonExistsResult);

        /** KeystoreCommonExistsResult isExists. */
        public isExists: boolean;

        /** KeystoreCommonExistsResult id. */
        public id: string;

        /**
         * Creates a new KeystoreCommonExistsResult instance using the specified properties.
         * @param [properties] Properties to set
         * @returns KeystoreCommonExistsResult instance
         */
        public static create(properties?: api.IKeystoreCommonExistsResult): api.KeystoreCommonExistsResult;

        /**
         * Encodes the specified KeystoreCommonExistsResult message. Does not implicitly {@link api.KeystoreCommonExistsResult.verify|verify} messages.
         * @param message KeystoreCommonExistsResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IKeystoreCommonExistsResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified KeystoreCommonExistsResult message, length delimited. Does not implicitly {@link api.KeystoreCommonExistsResult.verify|verify} messages.
         * @param message KeystoreCommonExistsResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IKeystoreCommonExistsResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a KeystoreCommonExistsResult message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns KeystoreCommonExistsResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.KeystoreCommonExistsResult;

        /**
         * Decodes a KeystoreCommonExistsResult message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns KeystoreCommonExistsResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.KeystoreCommonExistsResult;

        /**
         * Verifies a KeystoreCommonExistsResult message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a KeystoreCommonExistsResult message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns KeystoreCommonExistsResult
         */
        public static fromObject(object: { [k: string]: any }): api.KeystoreCommonExistsResult;

        /**
         * Creates a plain object from a KeystoreCommonExistsResult message. Also converts values to other types if specified.
         * @param message KeystoreCommonExistsResult
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.KeystoreCommonExistsResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this KeystoreCommonExistsResult to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a KeystoreCommonAccountsParam. */
    interface IKeystoreCommonAccountsParam {

        /** KeystoreCommonAccountsParam id */
        id?: (string|null);
    }

    /** Represents a KeystoreCommonAccountsParam. */
    class KeystoreCommonAccountsParam implements IKeystoreCommonAccountsParam {

        /**
         * Constructs a new KeystoreCommonAccountsParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IKeystoreCommonAccountsParam);

        /** KeystoreCommonAccountsParam id. */
        public id: string;

        /**
         * Creates a new KeystoreCommonAccountsParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns KeystoreCommonAccountsParam instance
         */
        public static create(properties?: api.IKeystoreCommonAccountsParam): api.KeystoreCommonAccountsParam;

        /**
         * Encodes the specified KeystoreCommonAccountsParam message. Does not implicitly {@link api.KeystoreCommonAccountsParam.verify|verify} messages.
         * @param message KeystoreCommonAccountsParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IKeystoreCommonAccountsParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified KeystoreCommonAccountsParam message, length delimited. Does not implicitly {@link api.KeystoreCommonAccountsParam.verify|verify} messages.
         * @param message KeystoreCommonAccountsParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IKeystoreCommonAccountsParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a KeystoreCommonAccountsParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns KeystoreCommonAccountsParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.KeystoreCommonAccountsParam;

        /**
         * Decodes a KeystoreCommonAccountsParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns KeystoreCommonAccountsParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.KeystoreCommonAccountsParam;

        /**
         * Verifies a KeystoreCommonAccountsParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a KeystoreCommonAccountsParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns KeystoreCommonAccountsParam
         */
        public static fromObject(object: { [k: string]: any }): api.KeystoreCommonAccountsParam;

        /**
         * Creates a plain object from a KeystoreCommonAccountsParam message. Also converts values to other types if specified.
         * @param message KeystoreCommonAccountsParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.KeystoreCommonAccountsParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this KeystoreCommonAccountsParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a SignParam. */
    interface ISignParam {

        /** SignParam id */
        id?: (string|null);

        /** SignParam password */
        password?: (string|null);

        /** SignParam derivedKey */
        derivedKey?: (string|null);

        /** SignParam chainType */
        chainType?: (string|null);

        /** SignParam address */
        address?: (string|null);

        /** SignParam input */
        input?: (google.protobuf.IAny|null);
    }

    /** Represents a SignParam. */
    class SignParam implements ISignParam {

        /**
         * Constructs a new SignParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.ISignParam);

        /** SignParam id. */
        public id: string;

        /** SignParam password. */
        public password: string;

        /** SignParam derivedKey. */
        public derivedKey: string;

        /** SignParam chainType. */
        public chainType: string;

        /** SignParam address. */
        public address: string;

        /** SignParam input. */
        public input?: (google.protobuf.IAny|null);

        /** SignParam key. */
        public key?: ("password"|"derivedKey");

        /**
         * Creates a new SignParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns SignParam instance
         */
        public static create(properties?: api.ISignParam): api.SignParam;

        /**
         * Encodes the specified SignParam message. Does not implicitly {@link api.SignParam.verify|verify} messages.
         * @param message SignParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.ISignParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified SignParam message, length delimited. Does not implicitly {@link api.SignParam.verify|verify} messages.
         * @param message SignParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.ISignParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a SignParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns SignParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.SignParam;

        /**
         * Decodes a SignParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns SignParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.SignParam;

        /**
         * Verifies a SignParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a SignParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns SignParam
         */
        public static fromObject(object: { [k: string]: any }): api.SignParam;

        /**
         * Creates a plain object from a SignParam message. Also converts values to other types if specified.
         * @param message SignParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.SignParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this SignParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of an ExternalAddressParam. */
    interface IExternalAddressParam {

        /** ExternalAddressParam id */
        id?: (string|null);

        /** ExternalAddressParam chainType */
        chainType?: (string|null);

        /** ExternalAddressParam externalIdx */
        externalIdx?: (number|null);
    }

    /** Represents an ExternalAddressParam. */
    class ExternalAddressParam implements IExternalAddressParam {

        /**
         * Constructs a new ExternalAddressParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IExternalAddressParam);

        /** ExternalAddressParam id. */
        public id: string;

        /** ExternalAddressParam chainType. */
        public chainType: string;

        /** ExternalAddressParam externalIdx. */
        public externalIdx: number;

        /**
         * Creates a new ExternalAddressParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns ExternalAddressParam instance
         */
        public static create(properties?: api.IExternalAddressParam): api.ExternalAddressParam;

        /**
         * Encodes the specified ExternalAddressParam message. Does not implicitly {@link api.ExternalAddressParam.verify|verify} messages.
         * @param message ExternalAddressParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IExternalAddressParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified ExternalAddressParam message, length delimited. Does not implicitly {@link api.ExternalAddressParam.verify|verify} messages.
         * @param message ExternalAddressParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IExternalAddressParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an ExternalAddressParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns ExternalAddressParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.ExternalAddressParam;

        /**
         * Decodes an ExternalAddressParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns ExternalAddressParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.ExternalAddressParam;

        /**
         * Verifies an ExternalAddressParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an ExternalAddressParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns ExternalAddressParam
         */
        public static fromObject(object: { [k: string]: any }): api.ExternalAddressParam;

        /**
         * Creates a plain object from an ExternalAddressParam message. Also converts values to other types if specified.
         * @param message ExternalAddressParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.ExternalAddressParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this ExternalAddressParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of an ExternalAddressResult. */
    interface IExternalAddressResult {

        /** ExternalAddressResult address */
        address?: (string|null);

        /** ExternalAddressResult derivedPath */
        derivedPath?: (string|null);

        /** ExternalAddressResult type */
        type?: (string|null);
    }

    /** Represents an ExternalAddressResult. */
    class ExternalAddressResult implements IExternalAddressResult {

        /**
         * Constructs a new ExternalAddressResult.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IExternalAddressResult);

        /** ExternalAddressResult address. */
        public address: string;

        /** ExternalAddressResult derivedPath. */
        public derivedPath: string;

        /** ExternalAddressResult type. */
        public type: string;

        /**
         * Creates a new ExternalAddressResult instance using the specified properties.
         * @param [properties] Properties to set
         * @returns ExternalAddressResult instance
         */
        public static create(properties?: api.IExternalAddressResult): api.ExternalAddressResult;

        /**
         * Encodes the specified ExternalAddressResult message. Does not implicitly {@link api.ExternalAddressResult.verify|verify} messages.
         * @param message ExternalAddressResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IExternalAddressResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified ExternalAddressResult message, length delimited. Does not implicitly {@link api.ExternalAddressResult.verify|verify} messages.
         * @param message ExternalAddressResult message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IExternalAddressResult, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an ExternalAddressResult message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns ExternalAddressResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.ExternalAddressResult;

        /**
         * Decodes an ExternalAddressResult message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns ExternalAddressResult
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.ExternalAddressResult;

        /**
         * Verifies an ExternalAddressResult message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an ExternalAddressResult message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns ExternalAddressResult
         */
        public static fromObject(object: { [k: string]: any }): api.ExternalAddressResult;

        /**
         * Creates a plain object from an ExternalAddressResult message. Also converts values to other types if specified.
         * @param message ExternalAddressResult
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.ExternalAddressResult, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this ExternalAddressResult to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of an ExternalAddressExtra. */
    interface IExternalAddressExtra {

        /** ExternalAddressExtra encXpub */
        encXpub?: (string|null);

        /** ExternalAddressExtra externalAddress */
        externalAddress?: (api.ExternalAddressExtra.IExternalAddress|null);
    }

    /** Represents an ExternalAddressExtra. */
    class ExternalAddressExtra implements IExternalAddressExtra {

        /**
         * Constructs a new ExternalAddressExtra.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IExternalAddressExtra);

        /** ExternalAddressExtra encXpub. */
        public encXpub: string;

        /** ExternalAddressExtra externalAddress. */
        public externalAddress?: (api.ExternalAddressExtra.IExternalAddress|null);

        /**
         * Creates a new ExternalAddressExtra instance using the specified properties.
         * @param [properties] Properties to set
         * @returns ExternalAddressExtra instance
         */
        public static create(properties?: api.IExternalAddressExtra): api.ExternalAddressExtra;

        /**
         * Encodes the specified ExternalAddressExtra message. Does not implicitly {@link api.ExternalAddressExtra.verify|verify} messages.
         * @param message ExternalAddressExtra message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IExternalAddressExtra, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified ExternalAddressExtra message, length delimited. Does not implicitly {@link api.ExternalAddressExtra.verify|verify} messages.
         * @param message ExternalAddressExtra message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IExternalAddressExtra, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an ExternalAddressExtra message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns ExternalAddressExtra
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.ExternalAddressExtra;

        /**
         * Decodes an ExternalAddressExtra message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns ExternalAddressExtra
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.ExternalAddressExtra;

        /**
         * Verifies an ExternalAddressExtra message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an ExternalAddressExtra message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns ExternalAddressExtra
         */
        public static fromObject(object: { [k: string]: any }): api.ExternalAddressExtra;

        /**
         * Creates a plain object from an ExternalAddressExtra message. Also converts values to other types if specified.
         * @param message ExternalAddressExtra
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.ExternalAddressExtra, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this ExternalAddressExtra to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    namespace ExternalAddressExtra {

        /** Properties of an ExternalAddress. */
        interface IExternalAddress {

            /** ExternalAddress address */
            address?: (string|null);

            /** ExternalAddress derivedPath */
            derivedPath?: (string|null);

            /** ExternalAddress type */
            type?: (string|null);
        }

        /** Represents an ExternalAddress. */
        class ExternalAddress implements IExternalAddress {

            /**
             * Constructs a new ExternalAddress.
             * @param [properties] Properties to set
             */
            constructor(properties?: api.ExternalAddressExtra.IExternalAddress);

            /** ExternalAddress address. */
            public address: string;

            /** ExternalAddress derivedPath. */
            public derivedPath: string;

            /** ExternalAddress type. */
            public type: string;

            /**
             * Creates a new ExternalAddress instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ExternalAddress instance
             */
            public static create(properties?: api.ExternalAddressExtra.IExternalAddress): api.ExternalAddressExtra.ExternalAddress;

            /**
             * Encodes the specified ExternalAddress message. Does not implicitly {@link api.ExternalAddressExtra.ExternalAddress.verify|verify} messages.
             * @param message ExternalAddress message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: api.ExternalAddressExtra.IExternalAddress, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ExternalAddress message, length delimited. Does not implicitly {@link api.ExternalAddressExtra.ExternalAddress.verify|verify} messages.
             * @param message ExternalAddress message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: api.ExternalAddressExtra.IExternalAddress, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an ExternalAddress message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ExternalAddress
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.ExternalAddressExtra.ExternalAddress;

            /**
             * Decodes an ExternalAddress message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ExternalAddress
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.ExternalAddressExtra.ExternalAddress;

            /**
             * Verifies an ExternalAddress message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an ExternalAddress message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ExternalAddress
             */
            public static fromObject(object: { [k: string]: any }): api.ExternalAddressExtra.ExternalAddress;

            /**
             * Creates a plain object from an ExternalAddress message. Also converts values to other types if specified.
             * @param message ExternalAddress
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: api.ExternalAddressExtra.ExternalAddress, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ExternalAddress to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };
        }
    }

    /** Properties of a BtcForkDeriveExtraParam. */
    interface IBtcForkDeriveExtraParam {

        /** BtcForkDeriveExtraParam network */
        network?: (string|null);

        /** BtcForkDeriveExtraParam segWit */
        segWit?: (string|null);
    }

    /** Represents a BtcForkDeriveExtraParam. */
    class BtcForkDeriveExtraParam implements IBtcForkDeriveExtraParam {

        /**
         * Constructs a new BtcForkDeriveExtraParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IBtcForkDeriveExtraParam);

        /** BtcForkDeriveExtraParam network. */
        public network: string;

        /** BtcForkDeriveExtraParam segWit. */
        public segWit: string;

        /**
         * Creates a new BtcForkDeriveExtraParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns BtcForkDeriveExtraParam instance
         */
        public static create(properties?: api.IBtcForkDeriveExtraParam): api.BtcForkDeriveExtraParam;

        /**
         * Encodes the specified BtcForkDeriveExtraParam message. Does not implicitly {@link api.BtcForkDeriveExtraParam.verify|verify} messages.
         * @param message BtcForkDeriveExtraParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IBtcForkDeriveExtraParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified BtcForkDeriveExtraParam message, length delimited. Does not implicitly {@link api.BtcForkDeriveExtraParam.verify|verify} messages.
         * @param message BtcForkDeriveExtraParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IBtcForkDeriveExtraParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a BtcForkDeriveExtraParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns BtcForkDeriveExtraParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.BtcForkDeriveExtraParam;

        /**
         * Decodes a BtcForkDeriveExtraParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns BtcForkDeriveExtraParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.BtcForkDeriveExtraParam;

        /**
         * Verifies a BtcForkDeriveExtraParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a BtcForkDeriveExtraParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns BtcForkDeriveExtraParam
         */
        public static fromObject(object: { [k: string]: any }): api.BtcForkDeriveExtraParam;

        /**
         * Creates a plain object from a BtcForkDeriveExtraParam message. Also converts values to other types if specified.
         * @param message BtcForkDeriveExtraParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.BtcForkDeriveExtraParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this BtcForkDeriveExtraParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a HdStoreExtendedPublicKeyParam. */
    interface IHdStoreExtendedPublicKeyParam {

        /** HdStoreExtendedPublicKeyParam id */
        id?: (string|null);

        /** HdStoreExtendedPublicKeyParam password */
        password?: (string|null);

        /** HdStoreExtendedPublicKeyParam chainType */
        chainType?: (string|null);

        /** HdStoreExtendedPublicKeyParam address */
        address?: (string|null);
    }

    /** Represents a HdStoreExtendedPublicKeyParam. */
    class HdStoreExtendedPublicKeyParam implements IHdStoreExtendedPublicKeyParam {

        /**
         * Constructs a new HdStoreExtendedPublicKeyParam.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IHdStoreExtendedPublicKeyParam);

        /** HdStoreExtendedPublicKeyParam id. */
        public id: string;

        /** HdStoreExtendedPublicKeyParam password. */
        public password: string;

        /** HdStoreExtendedPublicKeyParam chainType. */
        public chainType: string;

        /** HdStoreExtendedPublicKeyParam address. */
        public address: string;

        /**
         * Creates a new HdStoreExtendedPublicKeyParam instance using the specified properties.
         * @param [properties] Properties to set
         * @returns HdStoreExtendedPublicKeyParam instance
         */
        public static create(properties?: api.IHdStoreExtendedPublicKeyParam): api.HdStoreExtendedPublicKeyParam;

        /**
         * Encodes the specified HdStoreExtendedPublicKeyParam message. Does not implicitly {@link api.HdStoreExtendedPublicKeyParam.verify|verify} messages.
         * @param message HdStoreExtendedPublicKeyParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IHdStoreExtendedPublicKeyParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified HdStoreExtendedPublicKeyParam message, length delimited. Does not implicitly {@link api.HdStoreExtendedPublicKeyParam.verify|verify} messages.
         * @param message HdStoreExtendedPublicKeyParam message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IHdStoreExtendedPublicKeyParam, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a HdStoreExtendedPublicKeyParam message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns HdStoreExtendedPublicKeyParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.HdStoreExtendedPublicKeyParam;

        /**
         * Decodes a HdStoreExtendedPublicKeyParam message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns HdStoreExtendedPublicKeyParam
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.HdStoreExtendedPublicKeyParam;

        /**
         * Verifies a HdStoreExtendedPublicKeyParam message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a HdStoreExtendedPublicKeyParam message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns HdStoreExtendedPublicKeyParam
         */
        public static fromObject(object: { [k: string]: any }): api.HdStoreExtendedPublicKeyParam;

        /**
         * Creates a plain object from a HdStoreExtendedPublicKeyParam message. Also converts values to other types if specified.
         * @param message HdStoreExtendedPublicKeyParam
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.HdStoreExtendedPublicKeyParam, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this HdStoreExtendedPublicKeyParam to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a HdStoreExtendedPublicKeyResponse. */
    interface IHdStoreExtendedPublicKeyResponse {

        /** HdStoreExtendedPublicKeyResponse extendedPublicKey */
        extendedPublicKey?: (string|null);
    }

    /** Represents a HdStoreExtendedPublicKeyResponse. */
    class HdStoreExtendedPublicKeyResponse implements IHdStoreExtendedPublicKeyResponse {

        /**
         * Constructs a new HdStoreExtendedPublicKeyResponse.
         * @param [properties] Properties to set
         */
        constructor(properties?: api.IHdStoreExtendedPublicKeyResponse);

        /** HdStoreExtendedPublicKeyResponse extendedPublicKey. */
        public extendedPublicKey: string;

        /**
         * Creates a new HdStoreExtendedPublicKeyResponse instance using the specified properties.
         * @param [properties] Properties to set
         * @returns HdStoreExtendedPublicKeyResponse instance
         */
        public static create(properties?: api.IHdStoreExtendedPublicKeyResponse): api.HdStoreExtendedPublicKeyResponse;

        /**
         * Encodes the specified HdStoreExtendedPublicKeyResponse message. Does not implicitly {@link api.HdStoreExtendedPublicKeyResponse.verify|verify} messages.
         * @param message HdStoreExtendedPublicKeyResponse message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: api.IHdStoreExtendedPublicKeyResponse, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified HdStoreExtendedPublicKeyResponse message, length delimited. Does not implicitly {@link api.HdStoreExtendedPublicKeyResponse.verify|verify} messages.
         * @param message HdStoreExtendedPublicKeyResponse message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: api.IHdStoreExtendedPublicKeyResponse, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a HdStoreExtendedPublicKeyResponse message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns HdStoreExtendedPublicKeyResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): api.HdStoreExtendedPublicKeyResponse;

        /**
         * Decodes a HdStoreExtendedPublicKeyResponse message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns HdStoreExtendedPublicKeyResponse
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): api.HdStoreExtendedPublicKeyResponse;

        /**
         * Verifies a HdStoreExtendedPublicKeyResponse message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a HdStoreExtendedPublicKeyResponse message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns HdStoreExtendedPublicKeyResponse
         */
        public static fromObject(object: { [k: string]: any }): api.HdStoreExtendedPublicKeyResponse;

        /**
         * Creates a plain object from a HdStoreExtendedPublicKeyResponse message. Also converts values to other types if specified.
         * @param message HdStoreExtendedPublicKeyResponse
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: api.HdStoreExtendedPublicKeyResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this HdStoreExtendedPublicKeyResponse to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }
}

/** Namespace google. */
export namespace google {

    /** Namespace protobuf. */
    namespace protobuf {

        /** Properties of an Any. */
        interface IAny {

            /** Any type_url */
            type_url?: (string|null);

            /** Any value */
            value?: (Uint8Array|null);
        }

        /** Represents an Any. */
        class Any implements IAny {

            /**
             * Constructs a new Any.
             * @param [properties] Properties to set
             */
            constructor(properties?: google.protobuf.IAny);

            /** Any type_url. */
            public type_url: string;

            /** Any value. */
            public value: Uint8Array;

            /**
             * Creates a new Any instance using the specified properties.
             * @param [properties] Properties to set
             * @returns Any instance
             */
            public static create(properties?: google.protobuf.IAny): google.protobuf.Any;

            /**
             * Encodes the specified Any message. Does not implicitly {@link google.protobuf.Any.verify|verify} messages.
             * @param message Any message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: google.protobuf.IAny, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified Any message, length delimited. Does not implicitly {@link google.protobuf.Any.verify|verify} messages.
             * @param message Any message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: google.protobuf.IAny, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an Any message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns Any
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): google.protobuf.Any;

            /**
             * Decodes an Any message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns Any
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): google.protobuf.Any;

            /**
             * Verifies an Any message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an Any message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns Any
             */
            public static fromObject(object: { [k: string]: any }): google.protobuf.Any;

            /**
             * Creates a plain object from an Any message. Also converts values to other types if specified.
             * @param message Any
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: google.protobuf.Any, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this Any to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };
        }
    }
}

/** Namespace transaction. */
export namespace transaction {

    /** Properties of an Utxo. */
    interface IUtxo {

        /** Utxo txHash */
        txHash?: (string|null);

        /** Utxo vout */
        vout?: (number|null);

        /** Utxo amount */
        amount?: (number|Long|null);

        /** Utxo address */
        address?: (string|null);

        /** Utxo scriptPubKey */
        scriptPubKey?: (string|null);

        /** Utxo derivedPath */
        derivedPath?: (string|null);

        /** Utxo sequence */
        sequence?: (number|Long|null);
    }

    /** Represents an Utxo. */
    class Utxo implements IUtxo {

        /**
         * Constructs a new Utxo.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.IUtxo);

        /** Utxo txHash. */
        public txHash: string;

        /** Utxo vout. */
        public vout: number;

        /** Utxo amount. */
        public amount: (number|Long);

        /** Utxo address. */
        public address: string;

        /** Utxo scriptPubKey. */
        public scriptPubKey: string;

        /** Utxo derivedPath. */
        public derivedPath: string;

        /** Utxo sequence. */
        public sequence: (number|Long);

        /**
         * Creates a new Utxo instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Utxo instance
         */
        public static create(properties?: transaction.IUtxo): transaction.Utxo;

        /**
         * Encodes the specified Utxo message. Does not implicitly {@link transaction.Utxo.verify|verify} messages.
         * @param message Utxo message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.IUtxo, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified Utxo message, length delimited. Does not implicitly {@link transaction.Utxo.verify|verify} messages.
         * @param message Utxo message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.IUtxo, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an Utxo message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns Utxo
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.Utxo;

        /**
         * Decodes an Utxo message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns Utxo
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.Utxo;

        /**
         * Verifies an Utxo message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an Utxo message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns Utxo
         */
        public static fromObject(object: { [k: string]: any }): transaction.Utxo;

        /**
         * Creates a plain object from an Utxo message. Also converts values to other types if specified.
         * @param message Utxo
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.Utxo, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this Utxo to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a BtcForkTxInput. */
    interface IBtcForkTxInput {

        /** BtcForkTxInput to */
        to?: (string|null);

        /** BtcForkTxInput amount */
        amount?: (number|Long|null);

        /** BtcForkTxInput unspents */
        unspents?: (transaction.IUtxo[]|null);

        /** BtcForkTxInput fee */
        fee?: (number|Long|null);

        /** BtcForkTxInput changeAddressIndex */
        changeAddressIndex?: (number|null);

        /** BtcForkTxInput changeAddress */
        changeAddress?: (string|null);

        /** BtcForkTxInput network */
        network?: (string|null);

        /** BtcForkTxInput segWit */
        segWit?: (string|null);
    }

    /** Represents a BtcForkTxInput. */
    class BtcForkTxInput implements IBtcForkTxInput {

        /**
         * Constructs a new BtcForkTxInput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.IBtcForkTxInput);

        /** BtcForkTxInput to. */
        public to: string;

        /** BtcForkTxInput amount. */
        public amount: (number|Long);

        /** BtcForkTxInput unspents. */
        public unspents: transaction.IUtxo[];

        /** BtcForkTxInput fee. */
        public fee: (number|Long);

        /** BtcForkTxInput changeAddressIndex. */
        public changeAddressIndex: number;

        /** BtcForkTxInput changeAddress. */
        public changeAddress: string;

        /** BtcForkTxInput network. */
        public network: string;

        /** BtcForkTxInput segWit. */
        public segWit: string;

        /**
         * Creates a new BtcForkTxInput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns BtcForkTxInput instance
         */
        public static create(properties?: transaction.IBtcForkTxInput): transaction.BtcForkTxInput;

        /**
         * Encodes the specified BtcForkTxInput message. Does not implicitly {@link transaction.BtcForkTxInput.verify|verify} messages.
         * @param message BtcForkTxInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.IBtcForkTxInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified BtcForkTxInput message, length delimited. Does not implicitly {@link transaction.BtcForkTxInput.verify|verify} messages.
         * @param message BtcForkTxInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.IBtcForkTxInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a BtcForkTxInput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns BtcForkTxInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.BtcForkTxInput;

        /**
         * Decodes a BtcForkTxInput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns BtcForkTxInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.BtcForkTxInput;

        /**
         * Verifies a BtcForkTxInput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a BtcForkTxInput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns BtcForkTxInput
         */
        public static fromObject(object: { [k: string]: any }): transaction.BtcForkTxInput;

        /**
         * Creates a plain object from a BtcForkTxInput message. Also converts values to other types if specified.
         * @param message BtcForkTxInput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.BtcForkTxInput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this BtcForkTxInput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a BtcForkSignedTxOutput. */
    interface IBtcForkSignedTxOutput {

        /** BtcForkSignedTxOutput signature */
        signature?: (string|null);

        /** BtcForkSignedTxOutput txHash */
        txHash?: (string|null);
    }

    /** Represents a BtcForkSignedTxOutput. */
    class BtcForkSignedTxOutput implements IBtcForkSignedTxOutput {

        /**
         * Constructs a new BtcForkSignedTxOutput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.IBtcForkSignedTxOutput);

        /** BtcForkSignedTxOutput signature. */
        public signature: string;

        /** BtcForkSignedTxOutput txHash. */
        public txHash: string;

        /**
         * Creates a new BtcForkSignedTxOutput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns BtcForkSignedTxOutput instance
         */
        public static create(properties?: transaction.IBtcForkSignedTxOutput): transaction.BtcForkSignedTxOutput;

        /**
         * Encodes the specified BtcForkSignedTxOutput message. Does not implicitly {@link transaction.BtcForkSignedTxOutput.verify|verify} messages.
         * @param message BtcForkSignedTxOutput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.IBtcForkSignedTxOutput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified BtcForkSignedTxOutput message, length delimited. Does not implicitly {@link transaction.BtcForkSignedTxOutput.verify|verify} messages.
         * @param message BtcForkSignedTxOutput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.IBtcForkSignedTxOutput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a BtcForkSignedTxOutput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns BtcForkSignedTxOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.BtcForkSignedTxOutput;

        /**
         * Decodes a BtcForkSignedTxOutput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns BtcForkSignedTxOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.BtcForkSignedTxOutput;

        /**
         * Verifies a BtcForkSignedTxOutput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a BtcForkSignedTxOutput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns BtcForkSignedTxOutput
         */
        public static fromObject(object: { [k: string]: any }): transaction.BtcForkSignedTxOutput;

        /**
         * Creates a plain object from a BtcForkSignedTxOutput message. Also converts values to other types if specified.
         * @param message BtcForkSignedTxOutput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.BtcForkSignedTxOutput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this BtcForkSignedTxOutput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of an OutPoint. */
    interface IOutPoint {

        /** OutPoint txHash */
        txHash?: (string|null);

        /** OutPoint index */
        index?: (number|null);
    }

    /** Represents an OutPoint. */
    class OutPoint implements IOutPoint {

        /**
         * Constructs a new OutPoint.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.IOutPoint);

        /** OutPoint txHash. */
        public txHash: string;

        /** OutPoint index. */
        public index: number;

        /**
         * Creates a new OutPoint instance using the specified properties.
         * @param [properties] Properties to set
         * @returns OutPoint instance
         */
        public static create(properties?: transaction.IOutPoint): transaction.OutPoint;

        /**
         * Encodes the specified OutPoint message. Does not implicitly {@link transaction.OutPoint.verify|verify} messages.
         * @param message OutPoint message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.IOutPoint, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified OutPoint message, length delimited. Does not implicitly {@link transaction.OutPoint.verify|verify} messages.
         * @param message OutPoint message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.IOutPoint, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes an OutPoint message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns OutPoint
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.OutPoint;

        /**
         * Decodes an OutPoint message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns OutPoint
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.OutPoint;

        /**
         * Verifies an OutPoint message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates an OutPoint message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns OutPoint
         */
        public static fromObject(object: { [k: string]: any }): transaction.OutPoint;

        /**
         * Creates a plain object from an OutPoint message. Also converts values to other types if specified.
         * @param message OutPoint
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.OutPoint, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this OutPoint to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a Witness. */
    interface IWitness {

        /** Witness lock */
        lock?: (string|null);

        /** Witness inputType */
        inputType?: (string|null);

        /** Witness outputType */
        outputType?: (string|null);
    }

    /** Represents a Witness. */
    class Witness implements IWitness {

        /**
         * Constructs a new Witness.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.IWitness);

        /** Witness lock. */
        public lock: string;

        /** Witness inputType. */
        public inputType: string;

        /** Witness outputType. */
        public outputType: string;

        /**
         * Creates a new Witness instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Witness instance
         */
        public static create(properties?: transaction.IWitness): transaction.Witness;

        /**
         * Encodes the specified Witness message. Does not implicitly {@link transaction.Witness.verify|verify} messages.
         * @param message Witness message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.IWitness, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified Witness message, length delimited. Does not implicitly {@link transaction.Witness.verify|verify} messages.
         * @param message Witness message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.IWitness, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a Witness message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns Witness
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.Witness;

        /**
         * Decodes a Witness message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns Witness
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.Witness;

        /**
         * Verifies a Witness message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a Witness message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns Witness
         */
        public static fromObject(object: { [k: string]: any }): transaction.Witness;

        /**
         * Creates a plain object from a Witness message. Also converts values to other types if specified.
         * @param message Witness
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.Witness, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this Witness to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a Script. */
    interface IScript {

        /** Script args */
        args?: (string|null);

        /** Script codeHash */
        codeHash?: (string|null);

        /** Script hashType */
        hashType?: (string|null);
    }

    /** Represents a Script. */
    class Script implements IScript {

        /**
         * Constructs a new Script.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.IScript);

        /** Script args. */
        public args: string;

        /** Script codeHash. */
        public codeHash: string;

        /** Script hashType. */
        public hashType: string;

        /**
         * Creates a new Script instance using the specified properties.
         * @param [properties] Properties to set
         * @returns Script instance
         */
        public static create(properties?: transaction.IScript): transaction.Script;

        /**
         * Encodes the specified Script message. Does not implicitly {@link transaction.Script.verify|verify} messages.
         * @param message Script message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.IScript, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified Script message, length delimited. Does not implicitly {@link transaction.Script.verify|verify} messages.
         * @param message Script message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.IScript, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a Script message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns Script
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.Script;

        /**
         * Decodes a Script message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns Script
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.Script;

        /**
         * Verifies a Script message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a Script message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns Script
         */
        public static fromObject(object: { [k: string]: any }): transaction.Script;

        /**
         * Creates a plain object from a Script message. Also converts values to other types if specified.
         * @param message Script
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.Script, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this Script to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a CellInput. */
    interface ICellInput {

        /** CellInput previousOutput */
        previousOutput?: (transaction.IOutPoint|null);

        /** CellInput since */
        since?: (string|null);
    }

    /** Represents a CellInput. */
    class CellInput implements ICellInput {

        /**
         * Constructs a new CellInput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ICellInput);

        /** CellInput previousOutput. */
        public previousOutput?: (transaction.IOutPoint|null);

        /** CellInput since. */
        public since: string;

        /**
         * Creates a new CellInput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns CellInput instance
         */
        public static create(properties?: transaction.ICellInput): transaction.CellInput;

        /**
         * Encodes the specified CellInput message. Does not implicitly {@link transaction.CellInput.verify|verify} messages.
         * @param message CellInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ICellInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified CellInput message, length delimited. Does not implicitly {@link transaction.CellInput.verify|verify} messages.
         * @param message CellInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ICellInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a CellInput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns CellInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.CellInput;

        /**
         * Decodes a CellInput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns CellInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.CellInput;

        /**
         * Verifies a CellInput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a CellInput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns CellInput
         */
        public static fromObject(object: { [k: string]: any }): transaction.CellInput;

        /**
         * Creates a plain object from a CellInput message. Also converts values to other types if specified.
         * @param message CellInput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.CellInput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this CellInput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a CachedCell. */
    interface ICachedCell {

        /** CachedCell capacity */
        capacity?: (number|Long|null);

        /** CachedCell lock */
        lock?: (transaction.IScript|null);

        /** CachedCell outPoint */
        outPoint?: (transaction.IOutPoint|null);

        /** CachedCell derivedPath */
        derivedPath?: (string|null);
    }

    /** Represents a CachedCell. */
    class CachedCell implements ICachedCell {

        /**
         * Constructs a new CachedCell.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ICachedCell);

        /** CachedCell capacity. */
        public capacity: (number|Long);

        /** CachedCell lock. */
        public lock?: (transaction.IScript|null);

        /** CachedCell outPoint. */
        public outPoint?: (transaction.IOutPoint|null);

        /** CachedCell derivedPath. */
        public derivedPath: string;

        /**
         * Creates a new CachedCell instance using the specified properties.
         * @param [properties] Properties to set
         * @returns CachedCell instance
         */
        public static create(properties?: transaction.ICachedCell): transaction.CachedCell;

        /**
         * Encodes the specified CachedCell message. Does not implicitly {@link transaction.CachedCell.verify|verify} messages.
         * @param message CachedCell message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ICachedCell, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified CachedCell message, length delimited. Does not implicitly {@link transaction.CachedCell.verify|verify} messages.
         * @param message CachedCell message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ICachedCell, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a CachedCell message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns CachedCell
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.CachedCell;

        /**
         * Decodes a CachedCell message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns CachedCell
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.CachedCell;

        /**
         * Verifies a CachedCell message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a CachedCell message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns CachedCell
         */
        public static fromObject(object: { [k: string]: any }): transaction.CachedCell;

        /**
         * Creates a plain object from a CachedCell message. Also converts values to other types if specified.
         * @param message CachedCell
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.CachedCell, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this CachedCell to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a CkbTxInput. */
    interface ICkbTxInput {

        /** CkbTxInput inputs */
        inputs?: (transaction.ICellInput[]|null);

        /** CkbTxInput witnesses */
        witnesses?: (transaction.IWitness[]|null);

        /** CkbTxInput cachedCells */
        cachedCells?: (transaction.ICachedCell[]|null);

        /** CkbTxInput txHash */
        txHash?: (string|null);
    }

    /** Represents a CkbTxInput. */
    class CkbTxInput implements ICkbTxInput {

        /**
         * Constructs a new CkbTxInput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ICkbTxInput);

        /** CkbTxInput inputs. */
        public inputs: transaction.ICellInput[];

        /** CkbTxInput witnesses. */
        public witnesses: transaction.IWitness[];

        /** CkbTxInput cachedCells. */
        public cachedCells: transaction.ICachedCell[];

        /** CkbTxInput txHash. */
        public txHash: string;

        /**
         * Creates a new CkbTxInput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns CkbTxInput instance
         */
        public static create(properties?: transaction.ICkbTxInput): transaction.CkbTxInput;

        /**
         * Encodes the specified CkbTxInput message. Does not implicitly {@link transaction.CkbTxInput.verify|verify} messages.
         * @param message CkbTxInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ICkbTxInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified CkbTxInput message, length delimited. Does not implicitly {@link transaction.CkbTxInput.verify|verify} messages.
         * @param message CkbTxInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ICkbTxInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a CkbTxInput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns CkbTxInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.CkbTxInput;

        /**
         * Decodes a CkbTxInput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns CkbTxInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.CkbTxInput;

        /**
         * Verifies a CkbTxInput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a CkbTxInput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns CkbTxInput
         */
        public static fromObject(object: { [k: string]: any }): transaction.CkbTxInput;

        /**
         * Creates a plain object from a CkbTxInput message. Also converts values to other types if specified.
         * @param message CkbTxInput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.CkbTxInput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this CkbTxInput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a CkbTxOutput. */
    interface ICkbTxOutput {

        /** CkbTxOutput txHash */
        txHash?: (string|null);

        /** CkbTxOutput witnesses */
        witnesses?: (string[]|null);
    }

    /** Represents a CkbTxOutput. */
    class CkbTxOutput implements ICkbTxOutput {

        /**
         * Constructs a new CkbTxOutput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ICkbTxOutput);

        /** CkbTxOutput txHash. */
        public txHash: string;

        /** CkbTxOutput witnesses. */
        public witnesses: string[];

        /**
         * Creates a new CkbTxOutput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns CkbTxOutput instance
         */
        public static create(properties?: transaction.ICkbTxOutput): transaction.CkbTxOutput;

        /**
         * Encodes the specified CkbTxOutput message. Does not implicitly {@link transaction.CkbTxOutput.verify|verify} messages.
         * @param message CkbTxOutput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ICkbTxOutput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified CkbTxOutput message, length delimited. Does not implicitly {@link transaction.CkbTxOutput.verify|verify} messages.
         * @param message CkbTxOutput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ICkbTxOutput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a CkbTxOutput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns CkbTxOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.CkbTxOutput;

        /**
         * Decodes a CkbTxOutput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns CkbTxOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.CkbTxOutput;

        /**
         * Verifies a CkbTxOutput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a CkbTxOutput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns CkbTxOutput
         */
        public static fromObject(object: { [k: string]: any }): transaction.CkbTxOutput;

        /**
         * Creates a plain object from a CkbTxOutput message. Also converts values to other types if specified.
         * @param message CkbTxOutput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.CkbTxOutput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this CkbTxOutput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a SubstrateRawTxIn. */
    interface ISubstrateRawTxIn {

        /** SubstrateRawTxIn rawData */
        rawData?: (string|null);
    }

    /** Represents a SubstrateRawTxIn. */
    class SubstrateRawTxIn implements ISubstrateRawTxIn {

        /**
         * Constructs a new SubstrateRawTxIn.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ISubstrateRawTxIn);

        /** SubstrateRawTxIn rawData. */
        public rawData: string;

        /**
         * Creates a new SubstrateRawTxIn instance using the specified properties.
         * @param [properties] Properties to set
         * @returns SubstrateRawTxIn instance
         */
        public static create(properties?: transaction.ISubstrateRawTxIn): transaction.SubstrateRawTxIn;

        /**
         * Encodes the specified SubstrateRawTxIn message. Does not implicitly {@link transaction.SubstrateRawTxIn.verify|verify} messages.
         * @param message SubstrateRawTxIn message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ISubstrateRawTxIn, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified SubstrateRawTxIn message, length delimited. Does not implicitly {@link transaction.SubstrateRawTxIn.verify|verify} messages.
         * @param message SubstrateRawTxIn message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ISubstrateRawTxIn, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a SubstrateRawTxIn message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns SubstrateRawTxIn
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.SubstrateRawTxIn;

        /**
         * Decodes a SubstrateRawTxIn message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns SubstrateRawTxIn
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.SubstrateRawTxIn;

        /**
         * Verifies a SubstrateRawTxIn message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a SubstrateRawTxIn message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns SubstrateRawTxIn
         */
        public static fromObject(object: { [k: string]: any }): transaction.SubstrateRawTxIn;

        /**
         * Creates a plain object from a SubstrateRawTxIn message. Also converts values to other types if specified.
         * @param message SubstrateRawTxIn
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.SubstrateRawTxIn, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this SubstrateRawTxIn to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a SubstrateTxOut. */
    interface ISubstrateTxOut {

        /** SubstrateTxOut signature */
        signature?: (string|null);
    }

    /** Represents a SubstrateTxOut. */
    class SubstrateTxOut implements ISubstrateTxOut {

        /**
         * Constructs a new SubstrateTxOut.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ISubstrateTxOut);

        /** SubstrateTxOut signature. */
        public signature: string;

        /**
         * Creates a new SubstrateTxOut instance using the specified properties.
         * @param [properties] Properties to set
         * @returns SubstrateTxOut instance
         */
        public static create(properties?: transaction.ISubstrateTxOut): transaction.SubstrateTxOut;

        /**
         * Encodes the specified SubstrateTxOut message. Does not implicitly {@link transaction.SubstrateTxOut.verify|verify} messages.
         * @param message SubstrateTxOut message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ISubstrateTxOut, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified SubstrateTxOut message, length delimited. Does not implicitly {@link transaction.SubstrateTxOut.verify|verify} messages.
         * @param message SubstrateTxOut message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ISubstrateTxOut, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a SubstrateTxOut message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns SubstrateTxOut
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.SubstrateTxOut;

        /**
         * Decodes a SubstrateTxOut message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns SubstrateTxOut
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.SubstrateTxOut;

        /**
         * Verifies a SubstrateTxOut message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a SubstrateTxOut message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns SubstrateTxOut
         */
        public static fromObject(object: { [k: string]: any }): transaction.SubstrateTxOut;

        /**
         * Creates a plain object from a SubstrateTxOut message. Also converts values to other types if specified.
         * @param message SubstrateTxOut
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.SubstrateTxOut, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this SubstrateTxOut to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a TronTxInput. */
    interface ITronTxInput {

        /** TronTxInput rawData */
        rawData?: (string|null);
    }

    /** Represents a TronTxInput. */
    class TronTxInput implements ITronTxInput {

        /**
         * Constructs a new TronTxInput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ITronTxInput);

        /** TronTxInput rawData. */
        public rawData: string;

        /**
         * Creates a new TronTxInput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns TronTxInput instance
         */
        public static create(properties?: transaction.ITronTxInput): transaction.TronTxInput;

        /**
         * Encodes the specified TronTxInput message. Does not implicitly {@link transaction.TronTxInput.verify|verify} messages.
         * @param message TronTxInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ITronTxInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified TronTxInput message, length delimited. Does not implicitly {@link transaction.TronTxInput.verify|verify} messages.
         * @param message TronTxInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ITronTxInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a TronTxInput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns TronTxInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.TronTxInput;

        /**
         * Decodes a TronTxInput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns TronTxInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.TronTxInput;

        /**
         * Verifies a TronTxInput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a TronTxInput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns TronTxInput
         */
        public static fromObject(object: { [k: string]: any }): transaction.TronTxInput;

        /**
         * Creates a plain object from a TronTxInput message. Also converts values to other types if specified.
         * @param message TronTxInput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.TronTxInput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this TronTxInput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a TronTxOutput. */
    interface ITronTxOutput {

        /** TronTxOutput signatures */
        signatures?: (string[]|null);
    }

    /** Represents a TronTxOutput. */
    class TronTxOutput implements ITronTxOutput {

        /**
         * Constructs a new TronTxOutput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ITronTxOutput);

        /** TronTxOutput signatures. */
        public signatures: string[];

        /**
         * Creates a new TronTxOutput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns TronTxOutput instance
         */
        public static create(properties?: transaction.ITronTxOutput): transaction.TronTxOutput;

        /**
         * Encodes the specified TronTxOutput message. Does not implicitly {@link transaction.TronTxOutput.verify|verify} messages.
         * @param message TronTxOutput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ITronTxOutput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified TronTxOutput message, length delimited. Does not implicitly {@link transaction.TronTxOutput.verify|verify} messages.
         * @param message TronTxOutput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ITronTxOutput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a TronTxOutput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns TronTxOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.TronTxOutput;

        /**
         * Decodes a TronTxOutput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns TronTxOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.TronTxOutput;

        /**
         * Verifies a TronTxOutput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a TronTxOutput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns TronTxOutput
         */
        public static fromObject(object: { [k: string]: any }): transaction.TronTxOutput;

        /**
         * Creates a plain object from a TronTxOutput message. Also converts values to other types if specified.
         * @param message TronTxOutput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.TronTxOutput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this TronTxOutput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a TronMessageInput. */
    interface ITronMessageInput {

        /** TronMessageInput value */
        value?: (string|null);

        /** TronMessageInput isHex */
        isHex?: (boolean|null);

        /** TronMessageInput isTronHeader */
        isTronHeader?: (boolean|null);
    }

    /** Represents a TronMessageInput. */
    class TronMessageInput implements ITronMessageInput {

        /**
         * Constructs a new TronMessageInput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ITronMessageInput);

        /** TronMessageInput value. */
        public value: string;

        /** TronMessageInput isHex. */
        public isHex: boolean;

        /** TronMessageInput isTronHeader. */
        public isTronHeader: boolean;

        /**
         * Creates a new TronMessageInput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns TronMessageInput instance
         */
        public static create(properties?: transaction.ITronMessageInput): transaction.TronMessageInput;

        /**
         * Encodes the specified TronMessageInput message. Does not implicitly {@link transaction.TronMessageInput.verify|verify} messages.
         * @param message TronMessageInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ITronMessageInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified TronMessageInput message, length delimited. Does not implicitly {@link transaction.TronMessageInput.verify|verify} messages.
         * @param message TronMessageInput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ITronMessageInput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a TronMessageInput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns TronMessageInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.TronMessageInput;

        /**
         * Decodes a TronMessageInput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns TronMessageInput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.TronMessageInput;

        /**
         * Verifies a TronMessageInput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a TronMessageInput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns TronMessageInput
         */
        public static fromObject(object: { [k: string]: any }): transaction.TronMessageInput;

        /**
         * Creates a plain object from a TronMessageInput message. Also converts values to other types if specified.
         * @param message TronMessageInput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.TronMessageInput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this TronMessageInput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }

    /** Properties of a TronMessageOutput. */
    interface ITronMessageOutput {

        /** TronMessageOutput signature */
        signature?: (string|null);
    }

    /** Represents a TronMessageOutput. */
    class TronMessageOutput implements ITronMessageOutput {

        /**
         * Constructs a new TronMessageOutput.
         * @param [properties] Properties to set
         */
        constructor(properties?: transaction.ITronMessageOutput);

        /** TronMessageOutput signature. */
        public signature: string;

        /**
         * Creates a new TronMessageOutput instance using the specified properties.
         * @param [properties] Properties to set
         * @returns TronMessageOutput instance
         */
        public static create(properties?: transaction.ITronMessageOutput): transaction.TronMessageOutput;

        /**
         * Encodes the specified TronMessageOutput message. Does not implicitly {@link transaction.TronMessageOutput.verify|verify} messages.
         * @param message TronMessageOutput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encode(message: transaction.ITronMessageOutput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Encodes the specified TronMessageOutput message, length delimited. Does not implicitly {@link transaction.TronMessageOutput.verify|verify} messages.
         * @param message TronMessageOutput message or plain object to encode
         * @param [writer] Writer to encode to
         * @returns Writer
         */
        public static encodeDelimited(message: transaction.ITronMessageOutput, writer?: $protobuf.Writer): $protobuf.Writer;

        /**
         * Decodes a TronMessageOutput message from the specified reader or buffer.
         * @param reader Reader or buffer to decode from
         * @param [length] Message length if known beforehand
         * @returns TronMessageOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): transaction.TronMessageOutput;

        /**
         * Decodes a TronMessageOutput message from the specified reader or buffer, length delimited.
         * @param reader Reader or buffer to decode from
         * @returns TronMessageOutput
         * @throws {Error} If the payload is not a reader or valid buffer
         * @throws {$protobuf.util.ProtocolError} If required fields are missing
         */
        public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): transaction.TronMessageOutput;

        /**
         * Verifies a TronMessageOutput message.
         * @param message Plain object to verify
         * @returns `null` if valid, otherwise the reason why it is not
         */
        public static verify(message: { [k: string]: any }): (string|null);

        /**
         * Creates a TronMessageOutput message from a plain object. Also converts values to their respective internal types.
         * @param object Plain object
         * @returns TronMessageOutput
         */
        public static fromObject(object: { [k: string]: any }): transaction.TronMessageOutput;

        /**
         * Creates a plain object from a TronMessageOutput message. Also converts values to other types if specified.
         * @param message TronMessageOutput
         * @param [options] Conversion options
         * @returns Plain object
         */
        public static toObject(message: transaction.TronMessageOutput, options?: $protobuf.IConversionOptions): { [k: string]: any };

        /**
         * Converts this TronMessageOutput to JSON.
         * @returns JSON object
         */
        public toJSON(): { [k: string]: any };
    }
}
