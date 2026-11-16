import { defineHandler } from 'nitro';
import { indexHtml } from '../../utils/swagger';

/** /api-docs -> /api-docs/ so the UI's relative asset URLs resolve (swagger-ui-express did the same). */
export default defineHandler((event) => {
  const { search } = event.url;
  const pathname =
    ((event.context as Record<string, unknown>)['originalPathname'] as string) ?? event.url.pathname;
  if (pathname.endsWith('/')) {
    event.res.headers.set('content-type', 'text/html; charset=utf-8');
    return indexHtml();
  }
  event.res.status = 301;
  event.res.headers.set('Location', `${pathname}/${search}`);
  return '';
});
