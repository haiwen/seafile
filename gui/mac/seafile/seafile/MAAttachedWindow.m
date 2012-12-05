#import "MAAttachedWindow.h"

#define MAATTACHEDWINDOW_DEFAULT_BACKGROUND_COLOR [NSColor colorWithCalibratedWhite:0.1 alpha:0.75]
#define MAATTACHEDWINDOW_DEFAULT_BORDER_COLOR [NSColor whiteColor]
#define MAATTACHEDWINDOW_SCALE_FACTOR [[NSScreen mainScreen] userSpaceScaleFactor]

@interface MAAttachedWindow (MAPrivateMethods)

// Geometry
- (void)_updateGeometry;
- (MAWindowPosition)_bestSideForAutomaticPosition;
- (float)_arrowInset;

// Drawing
- (void)_updateBackground;
- (NSColor *)_backgroundColorPatternImage;
- (NSBezierPath *)_backgroundPath;
- (void)_appendArrowToPath: (NSBezierPath *)path;
- (void)_redisplay;

@end

@implementation MAAttachedWindow


#pragma mark Initializers


- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                          inWindow: (NSWindow *)window
                            onSide: (MAWindowPosition)side
                        atDistance: (float)distance
{
    // Insist on having a valid view.
    if (!view) {
        return nil;
    }

    // Create dummy initial contentRect for window.
    NSRect contentRect = NSZeroRect;
    contentRect.size = [view frame].size;

    if ((self = [super initWithContentRect: contentRect
                                 styleMask: NSBorderlessWindowMask
                                   backing: NSBackingStoreBuffered
                                     defer: NO])) {
        _view = view;
        _window = window;
        _point = point;
        _side = side;
        _distance = distance;

        // Configure window characteristics.
        [super setBackgroundColor: [NSColor clearColor]];
        [self setMovableByWindowBackground: NO];
        [self setExcludedFromWindowsMenu: YES];
        [self setAlphaValue: 1.0];
        [self setOpaque: NO];
        [self setHasShadow: YES];
        [self useOptimizedDrawing: YES];

        // Set up some sensible defaults for display.
        _MABackgroundColor = [MAATTACHEDWINDOW_DEFAULT_BACKGROUND_COLOR copy];
        borderColor = [MAATTACHEDWINDOW_DEFAULT_BORDER_COLOR copy];
        borderWidth = 2.0;
        viewMargin = 2.0;
        arrowBaseWidth = 20.0;
        arrowHeight = 16.0;
        hasArrow = YES;
        cornerRadius = 8.0;
        drawsRoundCornerBesideArrow = YES;
        _resizing = NO;

        // Work out what side to put the window on if it's "automatic".
        if (_side == MAPositionAutomatic) {
            _side = [self _bestSideForAutomaticPosition];
        }

        // Configure our initial geometry.
        [self _updateGeometry];

        // Update the background.
        [self _updateBackground];

        // Add view as subview of our contentView.
        [[self contentView] addSubview: _view];

        // Subscribe to notifications for when we change size.
        [[NSNotificationCenter defaultCenter] addObserver: self
                                                 selector: @selector(windowDidResize:)
                                                     name: NSWindowDidResizeNotification
                                                   object: self];
    }
    return self;
}


- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                          inWindow: (NSWindow *)window
                        atDistance: (float)distance
{
    return [self initWithView: view
              attachedToPoint: point
                     inWindow: window
                       onSide: MAPositionAutomatic
                   atDistance: distance];
}


- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                            onSide: (MAWindowPosition)side
                        atDistance: (float)distance
{
    return [self initWithView: view
              attachedToPoint: point
                     inWindow: nil
                       onSide: side
                   atDistance: distance];
}


- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                        atDistance: (float)distance
{
    return [self initWithView: view
              attachedToPoint: point
                     inWindow: nil
                       onSide: MAPositionAutomatic
                   atDistance: distance];
}


- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                          inWindow: (NSWindow *)window
{
    return [self initWithView: view
              attachedToPoint: point
                     inWindow: window
                       onSide: MAPositionAutomatic
                   atDistance: 0];
}


- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
                            onSide: (MAWindowPosition)side
{
    return [self initWithView: view
              attachedToPoint: point
                     inWindow: nil
                       onSide: side
                   atDistance: 0];
}


- (MAAttachedWindow *)initWithView: (NSView *)view
                   attachedToPoint: (NSPoint)point
{
    return [self initWithView: view
              attachedToPoint: point
                     inWindow: nil
                       onSide: MAPositionAutomatic
                   atDistance: 0];
}


- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver: self];
    [borderColor release];
    [_MABackgroundColor release];

    [super dealloc];
}


#pragma mark Geometry


- (void)_updateGeometry
{
    NSRect contentRect = NSZeroRect;
    contentRect.size = [_view frame].size;

    // Account for viewMargin.
    _viewFrame = NSMakeRect(viewMargin * MAATTACHEDWINDOW_SCALE_FACTOR,
                            viewMargin * MAATTACHEDWINDOW_SCALE_FACTOR,
                            [_view frame].size.width, [_view frame].size.height);
    contentRect = NSInsetRect(contentRect,
                              -viewMargin * MAATTACHEDWINDOW_SCALE_FACTOR,
                              -viewMargin * MAATTACHEDWINDOW_SCALE_FACTOR);

    // Account for arrowHeight in new window frame.
    // Note: we always leave room for the arrow, even if it currently set to
    // not be shown. This is so it can easily be toggled whilst the window
    // is visible, without altering the window's frame origin point.
    float scaledArrowHeight = arrowHeight * MAATTACHEDWINDOW_SCALE_FACTOR;
    switch (_side) {
        case MAPositionLeft:
        case MAPositionLeftTop:
        case MAPositionLeftBottom:
            contentRect.size.width += scaledArrowHeight;
            break;
        case MAPositionRight:
        case MAPositionRightTop:
        case MAPositionRightBottom:
            _viewFrame.origin.x += scaledArrowHeight;
            contentRect.size.width += scaledArrowHeight;
            break;
        case MAPositionTop:
        case MAPositionTopLeft:
        case MAPositionTopRight:
            _viewFrame.origin.y += scaledArrowHeight;
            contentRect.size.height += scaledArrowHeight;
            break;
        case MAPositionBottom:
        case MAPositionBottomLeft:
        case MAPositionBottomRight:
            contentRect.size.height += scaledArrowHeight;
            break;
        default:
            break; // won't happen, but this satisfies gcc with -Wall
    }

    // Position frame origin appropriately for _side, accounting for arrow-inset.
    contentRect.origin = (_window) ? [_window convertBaseToScreen: _point]:  _point;
    float arrowInset = [self _arrowInset];
    float halfWidth = contentRect.size.width / 2.0;
    float halfHeight = contentRect.size.height / 2.0;
    switch (_side) {
        case MAPositionTopLeft:
            contentRect.origin.x -= contentRect.size.width - arrowInset;
            break;
        case MAPositionTop:
            contentRect.origin.x -= halfWidth;
            break;
        case MAPositionTopRight:
            contentRect.origin.x -= arrowInset;
            break;
        case MAPositionBottomLeft:
            contentRect.origin.y -= contentRect.size.height;
            contentRect.origin.x -= contentRect.size.width - arrowInset;
            break;
        case MAPositionBottom:
            contentRect.origin.y -= contentRect.size.height;
            contentRect.origin.x -= halfWidth;
            break;
        case MAPositionBottomRight:
            contentRect.origin.x -= arrowInset;
            contentRect.origin.y -= contentRect.size.height;
            break;
        case MAPositionLeftTop:
            contentRect.origin.x -= contentRect.size.width;
            contentRect.origin.y -= arrowInset;
            break;
        case MAPositionLeft:
            contentRect.origin.x -= contentRect.size.width;
            contentRect.origin.y -= halfHeight;
            break;
        case MAPositionLeftBottom:
            contentRect.origin.x -= contentRect.size.width;
            contentRect.origin.y -= contentRect.size.height - arrowInset;
            break;
        case MAPositionRightTop:
            contentRect.origin.y -= arrowInset;
            break;
        case MAPositionRight:
            contentRect.origin.y -= halfHeight;
            break;
        case MAPositionRightBottom:
            contentRect.origin.y -= contentRect.size.height - arrowInset;
            break;
        default:
            break; // won't happen, but this satisfies gcc with -Wall
    }

    // Account for _distance in new window frame.
    switch (_side) {
        case MAPositionLeft:
        case MAPositionLeftTop:
        case MAPositionLeftBottom:
            contentRect.origin.x -= _distance;
            break;
        case MAPositionRight:
        case MAPositionRightTop:
        case MAPositionRightBottom:
            contentRect.origin.x += _distance;
            break;
        case MAPositionTop:
        case MAPositionTopLeft:
        case MAPositionTopRight:
            contentRect.origin.y += _distance;
            break;
        case MAPositionBottom:
        case MAPositionBottomLeft:
        case MAPositionBottomRight:
            contentRect.origin.y -= _distance;
            break;
        default:
            break; // won't happen, but this satisfies gcc with -Wall
    }

    // Reconfigure window and view frames appropriately.
    [self setFrame: contentRect display: NO];
    [_view setFrame: _viewFrame];
}


- (MAWindowPosition)_bestSideForAutomaticPosition
{
    // Get all relevant geometry in screen coordinates.
    NSRect screenFrame;
    if (_window && [_window screen]) {
        screenFrame = [[_window screen] visibleFrame];
    } else {
        screenFrame = [[NSScreen mainScreen] visibleFrame];
    }
    NSPoint pointOnScreen = (_window) ? [_window convertBaseToScreen: _point] : _point;
    NSSize viewSize = [_view frame].size;
    viewSize.width += (viewMargin * MAATTACHEDWINDOW_SCALE_FACTOR) * 2.0;
    viewSize.height += (viewMargin * MAATTACHEDWINDOW_SCALE_FACTOR) * 2.0;
    MAWindowPosition side = MAPositionBottom; // By default, position us centered below.
    float scaledArrowHeight = (arrowHeight * MAATTACHEDWINDOW_SCALE_FACTOR) + _distance;

    // We'd like to display directly below the specified point, since this gives a
    // sense of a relationship between the point and this window. Check there's room.
    if (pointOnScreen.y - viewSize.height - scaledArrowHeight < NSMinY(screenFrame)) {
        // We'd go off the bottom of the screen. Try the right.
        if (pointOnScreen.x + viewSize.width + scaledArrowHeight >= NSMaxX(screenFrame)) {
            // We'd go off the right of the screen. Try the left.
            if (pointOnScreen.x - viewSize.width - scaledArrowHeight < NSMinX(screenFrame)) {
                // We'd go off the left of the screen. Try the top.
                if (pointOnScreen.y + viewSize.height + scaledArrowHeight < NSMaxY(screenFrame)) {
                    side = MAPositionTop;
                }
            } else {
                side = MAPositionLeft;
            }
        } else {
            side = MAPositionRight;
        }
    }

    float halfWidth = viewSize.width / 2.0;
    float halfHeight = viewSize.height / 2.0;

    NSRect parentFrame = (_window) ? [_window frame]: screenFrame;
    float arrowInset = [self _arrowInset];

    // We're currently at a primary side.
    // Try to avoid going outwith the parent area in the secondary dimension,
    // by checking to see if an appropriate corner side would be better.
    switch (side) {
        case MAPositionBottom:
        case MAPositionTop:
            // Check to see if we go beyond the left edge of the parent area.
            if (pointOnScreen.x - halfWidth < NSMinX(parentFrame)) {
                // We go beyond the left edge. Try using right position.
                if (pointOnScreen.x + viewSize.width - arrowInset < NSMaxX(screenFrame)) {
                    // We'd still be on-screen using right, so use it.
                    if (side == MAPositionBottom) {
                        side = MAPositionBottomRight;
                    } else {
                        side = MAPositionTopRight;
                    }
                }
            } else if (pointOnScreen.x + halfWidth >= NSMaxX(parentFrame)) {
                // We go beyond the right edge. Try using left position.
                if (pointOnScreen.x - viewSize.width + arrowInset >= NSMinX(screenFrame)) {
                    // We'd still be on-screen using left, so use it.
                    if (side == MAPositionBottom) {
                        side = MAPositionBottomLeft;
                    } else {
                        side = MAPositionTopLeft;
                    }
                }
            }
            break;
        case MAPositionRight:
        case MAPositionLeft:
            // Check to see if we go beyond the bottom edge of the parent area.
            if (pointOnScreen.y - halfHeight < NSMinY(parentFrame)) {
                // We go beyond the bottom edge. Try using top position.
                if (pointOnScreen.y + viewSize.height - arrowInset < NSMaxY(screenFrame)) {
                    // We'd still be on-screen using top, so use it.
                    if (side == MAPositionRight) {
                        side = MAPositionRightTop;
                    } else {
                        side = MAPositionLeftTop;
                    }
                }
            } else if (pointOnScreen.y + halfHeight >= NSMaxY(parentFrame)) {
                // We go beyond the top edge. Try using bottom position.
                if (pointOnScreen.y - viewSize.height + arrowInset >= NSMinY(screenFrame)) {
                    // We'd still be on-screen using bottom, so use it.
                    if (side == MAPositionRight) {
                        side = MAPositionRightBottom;
                    } else {
                        side = MAPositionLeftBottom;
                    }
                }
            }
            break;
        default:
            break; // won't happen, but this satisfies gcc with -Wall
    }

    return side;
}


- (float)_arrowInset
{
    float cornerInset = (drawsRoundCornerBesideArrow) ? cornerRadius : 0;
    return (cornerInset + (arrowBaseWidth / 2.0)) * MAATTACHEDWINDOW_SCALE_FACTOR;
}


#pragma mark Drawing
- (void)_updateBackground
{
    // Call NSWindow's implementation of -setBackgroundColor: because we override
    // it in this class to let us set the entire background image of the window
    // as an NSColor patternImage.
    NSDisableScreenUpdates ();
    [super setBackgroundColor: [self _backgroundColorPatternImage]];
    if ([self isVisible]) {
        [self display];
        [self invalidateShadow];
    }
    NSEnableScreenUpdates ();
}


- (NSColor *)_backgroundColorPatternImage
{
    NSImage *bg = [[NSImage alloc] initWithSize: [self frame].size];
    NSRect bgRect = NSZeroRect;
    bgRect.size = [bg size];

    [bg lockFocus];
    NSBezierPath *bgPath = [self _backgroundPath];
    [NSGraphicsContext saveGraphicsState];
    [bgPath addClip];

    // Draw background.
    [_MABackgroundColor set];
    [bgPath fill];

    // Draw border if appropriate.
    if (borderWidth > 0) {
        // Double the borderWidth since we're drawing inside the path.
        [bgPath setLineWidth: (borderWidth * 2.0) * MAATTACHEDWINDOW_SCALE_FACTOR];
        [borderColor set];
        [bgPath stroke];
    }

    [NSGraphicsContext restoreGraphicsState];
    [bg unlockFocus];

    return [NSColor colorWithPatternImage: [bg autorelease]];
}


- (NSBezierPath *)_backgroundPath
{
    /*
     Construct path for window background, taking account of:
     1. hasArrow
     2. _side
     3. drawsRoundCornerBesideArrow
     4. arrowBaseWidth
     5. arrowHeight
     6. cornerRadius
     */

    float scaleFactor = MAATTACHEDWINDOW_SCALE_FACTOR;
    float scaledRadius = cornerRadius * scaleFactor;
    float scaledArrowWidth = arrowBaseWidth * scaleFactor;
    float halfArrowWidth = scaledArrowWidth / 2.0;
    NSRect contentArea = NSInsetRect(_viewFrame,
                                     -viewMargin * scaleFactor,
                                     -viewMargin * scaleFactor);
    float minX = NSMinX(contentArea) * scaleFactor;
    float midX = NSMidX(contentArea) * scaleFactor;
    float maxX = NSMaxX(contentArea) * scaleFactor;
    float minY = NSMinY(contentArea) * scaleFactor;
    float midY = NSMidY(contentArea) * scaleFactor;
    float maxY = NSMaxY(contentArea) * scaleFactor;

    NSBezierPath *path = [NSBezierPath bezierPath];
    [path setLineJoinStyle: NSRoundLineJoinStyle];

    // Begin at top-left. This will be either after the rounded corner, or
    // at the top-left point if cornerRadius is zero and/or we're drawing
    // the arrow at the top-left or left-top without a rounded corner.
    NSPoint currPt = NSMakePoint(minX, maxY);
    if (scaledRadius > 0 &&
        (drawsRoundCornerBesideArrow ||
         (_side != MAPositionBottomRight && _side != MAPositionRightBottom))
        ) {
        currPt.x += scaledRadius;
    }

    NSPoint endOfLine = NSMakePoint(maxX, maxY);
    BOOL shouldDrawNextCorner = NO;
    if (scaledRadius > 0 &&
        (drawsRoundCornerBesideArrow ||
         (_side != MAPositionBottomLeft && _side != MAPositionLeftBottom))
        ) {
        endOfLine.x -= scaledRadius;
        shouldDrawNextCorner = YES;
    }

    [path moveToPoint: currPt];

    // If arrow should be drawn at top-left point, draw it.
    if (_side == MAPositionBottomRight) {
        [self _appendArrowToPath: path];
    } else if (_side == MAPositionBottom) {
        // Line to relevant point before arrow.
        [path lineToPoint: NSMakePoint(midX - halfArrowWidth, maxY)];
        // Draw arrow.
        [self _appendArrowToPath: path];
    } else if (_side == MAPositionBottomLeft) {
        // Line to relevant point before arrow.
        [path lineToPoint: NSMakePoint(endOfLine.x - scaledArrowWidth, maxY)];
        // Draw arrow.
        [self _appendArrowToPath: path];
    }

    // Line to end of this side.
    [path lineToPoint: endOfLine];

    // Rounded corner on top-right.
    if (shouldDrawNextCorner) {
        [path appendBezierPathWithArcFromPoint: NSMakePoint(maxX, maxY)
                                       toPoint: NSMakePoint(maxX, maxY - scaledRadius)
                                        radius: scaledRadius];
    }


    // Draw the right side, beginning at the top-right.
    endOfLine = NSMakePoint(maxX, minY);
    shouldDrawNextCorner = NO;
    if (scaledRadius > 0 &&
        (drawsRoundCornerBesideArrow ||
         (_side != MAPositionTopLeft && _side != MAPositionLeftTop))
        ) {
        endOfLine.y += scaledRadius;
        shouldDrawNextCorner = YES;
    }

    // If arrow should be drawn at right-top point, draw it.
    if (_side == MAPositionLeftBottom) {
        [self _appendArrowToPath: path];
    } else if (_side == MAPositionLeft) {
        // Line to relevant point before arrow.
        [path lineToPoint: NSMakePoint(maxX, midY + halfArrowWidth)];
        // Draw arrow.
        [self _appendArrowToPath: path];
    } else if (_side == MAPositionLeftTop) {
        // Line to relevant point before arrow.
        [path lineToPoint: NSMakePoint(maxX, endOfLine.y + scaledArrowWidth)];
        // Draw arrow.
        [self _appendArrowToPath: path];
    }

    // Line to end of this side.
    [path lineToPoint: endOfLine];

    // Rounded corner on bottom-right.
    if (shouldDrawNextCorner) {
        [path appendBezierPathWithArcFromPoint: NSMakePoint(maxX, minY)
                                       toPoint: NSMakePoint(maxX - scaledRadius, minY)
                                        radius: scaledRadius];
    }


    // Draw the bottom side, beginning at the bottom-right.
    endOfLine = NSMakePoint(minX, minY);
    shouldDrawNextCorner = NO;
    if (scaledRadius > 0 &&
        (drawsRoundCornerBesideArrow ||
         (_side != MAPositionTopRight && _side != MAPositionRightTop))
        ) {
        endOfLine.x += scaledRadius;
        shouldDrawNextCorner = YES;
    }

    // If arrow should be drawn at bottom-right point, draw it.
    if (_side == MAPositionTopLeft) {
        [self _appendArrowToPath: path];
    } else if (_side == MAPositionTop) {
        // Line to relevant point before arrow.
        [path lineToPoint: NSMakePoint(midX + halfArrowWidth, minY)];
        // Draw arrow.
        [self _appendArrowToPath: path];
    } else if (_side == MAPositionTopRight) {
        // Line to relevant point before arrow.
        [path lineToPoint: NSMakePoint(endOfLine.x + scaledArrowWidth, minY)];
        // Draw arrow.
        [self _appendArrowToPath: path];
    }

    // Line to end of this side.
    [path lineToPoint: endOfLine];

    // Rounded corner on bottom-left.
    if (shouldDrawNextCorner) {
        [path appendBezierPathWithArcFromPoint: NSMakePoint(minX, minY)
                                       toPoint: NSMakePoint(minX, minY + scaledRadius)
                                        radius: scaledRadius];
    }


    // Draw the left side, beginning at the bottom-left.
    endOfLine = NSMakePoint(minX, maxY);
    shouldDrawNextCorner = NO;
    if (scaledRadius > 0 &&
        (drawsRoundCornerBesideArrow ||
         (_side != MAPositionRightBottom && _side != MAPositionBottomRight))
        ) {
        endOfLine.y -= scaledRadius;
        shouldDrawNextCorner = YES;
    }

    // If arrow should be drawn at left-bottom point, draw it.
    if (_side == MAPositionRightTop) {
        [self _appendArrowToPath: path];
    } else if (_side == MAPositionRight) {
        // Line to relevant point before arrow.
        [path lineToPoint: NSMakePoint(minX, midY - halfArrowWidth)];
        // Draw arrow.
        [self _appendArrowToPath: path];
    } else if (_side == MAPositionRightBottom) {
        // Line to relevant point before arrow.
        [path lineToPoint: NSMakePoint(minX, endOfLine.y - scaledArrowWidth)];
        // Draw arrow.
        [self _appendArrowToPath: path];
    }

    // Line to end of this side.
    [path lineToPoint: endOfLine];

    // Rounded corner on top-left.
    if (shouldDrawNextCorner) {
        [path appendBezierPathWithArcFromPoint: NSMakePoint(minX, maxY)
                                       toPoint: NSMakePoint(minX + scaledRadius, maxY)
                                        radius: scaledRadius];
    }

    [path closePath];
    return path;
}


- (void)_appendArrowToPath: (NSBezierPath *)path
{
    if (!hasArrow) {
        return;
    }

    float scaleFactor = MAATTACHEDWINDOW_SCALE_FACTOR;
    float scaledArrowWidth = arrowBaseWidth * scaleFactor;
    float halfArrowWidth = scaledArrowWidth / 2.0;
    float scaledArrowHeight = arrowHeight * scaleFactor;
    NSPoint currPt = [path currentPoint];
    NSPoint tipPt = currPt;
    NSPoint endPt = currPt;

    // Note: we always build the arrow path in a clockwise direction.
    switch (_side) {
        case MAPositionLeft:
        case MAPositionLeftTop:
        case MAPositionLeftBottom:
            // Arrow points towards right. We're starting from the top.
            tipPt.x += scaledArrowHeight;
            tipPt.y -= halfArrowWidth;
            endPt.y -= scaledArrowWidth;
            break;
        case MAPositionRight:
        case MAPositionRightTop:
        case MAPositionRightBottom:
            // Arrow points towards left. We're starting from the bottom.
            tipPt.x -= scaledArrowHeight;
            tipPt.y += halfArrowWidth;
            endPt.y += scaledArrowWidth;
            break;
        case MAPositionTop:
        case MAPositionTopLeft:
        case MAPositionTopRight:
            // Arrow points towards bottom. We're starting from the right.
            tipPt.y -= scaledArrowHeight;
            tipPt.x -= halfArrowWidth;
            endPt.x -= scaledArrowWidth;
            break;
        case MAPositionBottom:
        case MAPositionBottomLeft:
        case MAPositionBottomRight:
            // Arrow points towards top. We're starting from the left.
            tipPt.y += scaledArrowHeight;
            tipPt.x += halfArrowWidth;
            endPt.x += scaledArrowWidth;
            break;
        default:
            break; // won't happen, but this satisfies gcc with -Wall
    }

    [path lineToPoint: tipPt];
    [path lineToPoint: endPt];
}


- (void)_redisplay
{
    if (_resizing) {
        return;
    }

    _resizing = YES;
    NSDisableScreenUpdates();
    [self _updateGeometry];
    [self _updateBackground];
    NSEnableScreenUpdates();
    _resizing = NO;
}


# pragma mark Window Behaviour


- (BOOL)canBecomeMainWindow
{
    return NO;
}


- (BOOL)canBecomeKeyWindow
{
    return YES;
}


- (BOOL)isExcludedFromWindowsMenu
{
    return YES;
}


- (BOOL)validateMenuItem: (NSMenuItem *)item
{
    if (_window) {
        return [_window validateMenuItem: item];
    }
    return [super validateMenuItem: item];
}


- (IBAction)performClose: (id)sender
{
    if (_window) {
        [_window performClose: sender];
    } else {
        [super performClose: sender];
    }
}


# pragma mark Notification handlers


- (void)windowDidResize: (NSNotification *)note
{
    [self _redisplay];
}


#pragma mark Accessors


- (NSColor *)windowBackgroundColor
{
    return [[_MABackgroundColor retain] autorelease];
}


- (void)setBackgroundColor: (NSColor *)value
{
    if (_MABackgroundColor != value) {
        [_MABackgroundColor release];
        _MABackgroundColor = [value copy];

        [self _updateBackground];
    }
}


- (NSColor *)borderColor
{
    return [[borderColor retain] autorelease];
}


- (void)setBorderColor: (NSColor *)value
{
    if (borderColor != value) {
        [borderColor release];
        borderColor = [value copy];

        [self _updateBackground];
    }
}


- (float)borderWidth
{
    return borderWidth;
}


- (void)setBorderWidth: (float)value
{
    if (borderWidth != value) {
        float maxBorderWidth = viewMargin;
        if (value <= maxBorderWidth) {
            borderWidth = value;
        } else {
            borderWidth = maxBorderWidth;
        }

        [self _updateBackground];
    }
}


- (float)viewMargin
{
    return viewMargin;
}


- (void)setViewMargin: (float)value
{
    if (viewMargin != value) {
        viewMargin = MAX(value, 0.0);

        // Adjust cornerRadius appropriately (which will also adjust arrowBaseWidth).
        [self setCornerRadius: cornerRadius];
    }
}


- (float)arrowBaseWidth
{
    return arrowBaseWidth;
}


- (void)setArrowBaseWidth: (float)value
{
    float maxWidth = (MIN(_viewFrame.size.width, _viewFrame.size.height) +
                      (viewMargin * 2.0)) - cornerRadius;
    if (drawsRoundCornerBesideArrow) {
        maxWidth -= cornerRadius;
    }
    if (value <= maxWidth) {
        arrowBaseWidth = value;
    } else {
        arrowBaseWidth = maxWidth;
    }

    [self _redisplay];
}


- (float)arrowHeight
{
    return arrowHeight;
}


- (void)setArrowHeight: (float)value
{
    if (arrowHeight != value) {
        arrowHeight = value;

        [self _redisplay];
    }
}


- (float)hasArrow
{
    return hasArrow;
}


- (void)setHasArrow: (float)value
{
    if (hasArrow != value) {
        hasArrow = value;

        [self _updateBackground];
    }
}


- (float)cornerRadius
{
    return cornerRadius;
}


- (void)setCornerRadius: (float)value
{
    float maxRadius = ((MIN(_viewFrame.size.width, _viewFrame.size.height) +
                        (viewMargin * 2.0)) - arrowBaseWidth) / 2.0;
    if (value <= maxRadius) {
        cornerRadius = value;
    } else {
        cornerRadius = maxRadius;
    }
    cornerRadius = MAX(cornerRadius, 0.0);

    // Adjust arrowBaseWidth appropriately.
    [self setArrowBaseWidth: arrowBaseWidth];
}


- (float)drawsRoundCornerBesideArrow
{
    return drawsRoundCornerBesideArrow;
}


- (void)setDrawsRoundCornerBesideArrow: (float)value
{
    if (drawsRoundCornerBesideArrow != value) {
        drawsRoundCornerBesideArrow = value;

        [self _redisplay];
    }
}


- (void)setBackgroundImage: (NSImage *)value
{
    if (value) {
        [self setBackgroundColor: [NSColor colorWithPatternImage: value]];
    }
}


@end
