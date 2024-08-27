import init, {
  initThreadPool,
  tdn_collect,
  setup_tracing_web,
} from '../wasm/prover/pkg/tlsn_extension_rs';

// The wasm module name is still 'tlsn_extension_rs'.
export const DEFAULT_LOGGING_FILTER: string = 'info,tlsn_extension_rs=debug';

export default class TDN {
  private startPromise: Promise<void>;
  private resolveStart!: () => void;
  private logging_filter: string;

  /**
   * Initializes a new instance of the TDN class.
   *
   * @param logging_filter - Optional logging filter string.
   *                         Defaults to DEFAULT_LOGGING_FILTER
   */
  constructor(logging_filter: string = DEFAULT_LOGGING_FILTER) {
    this.logging_filter = logging_filter;

    this.startPromise = new Promise((resolve) => {
      this.resolveStart = resolve;
    });
    this.start();
  }

  async start() {
    // console.log('start');
    const numConcurrency = navigator.hardwareConcurrency;
    // console.log('!@# navigator.hardwareConcurrency=', numConcurrency);
    await init();
    setup_tracing_web(this.logging_filter);
    // const res = await init();
    // console.log('!@# res.memory=', res.memory);
    // 6422528 ~= 6.12 mb
    // console.log('!@# res.memory.buffer.length=', res.memory.buffer.byteLength);
    await initThreadPool(numConcurrency);
    this.resolveStart();
  }

  async waitForStart() {
    return this.startPromise;
  }

  async collectSessionMaterials(
    url: string,
    options?: {
      method?: string;
      headers?: { [key: string]: string };
      body?: string;
      maxSentData?: number;
      maxRecvData?: number;
      maxTranscriptSize?: number;
      notaryUrl?: string;
      websocketProxyUrl?: string;
    },
  ) {
    await this.waitForStart();
    // console.log('worker', url, {
    //   ...options,
    //   notaryUrl: options?.notaryUrl,
    //   websocketProxyUrl: options?.websocketProxyUrl,
    // });
    const resProver = await tdn_collect(url, {
      ...options,
      notaryUrl: options?.notaryUrl,
      websocketProxyUrl: options?.websocketProxyUrl,
    });
    const resJSON = JSON.parse(resProver);
    // console.log('!@# resProver,resJSON=', { resProver, resJSON });
    // console.log('!@# resAfter.memory=', resJSON.memory);
    // 1105920000 ~= 1.03 gb
    // console.log(
    //   '!@# resAfter.memory.buffer.length=',
    //   resJSON.memory?.buffer?.byteLength,
    // );

    return resJSON;
  }
}
